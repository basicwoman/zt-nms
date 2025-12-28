package proxy

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	netconfDefaultPort    = 830
	netconfMessageEnd     = "]]>]]>"
	netconf10MessageEnd   = "]]>]]>"
	netconf11ChunkedMode  = "\n##\n"
)

// NetconfAdapter implements the ProtocolAdapter interface for NETCONF
type NetconfAdapter struct {
	config  *NetconfConfig
	logger  *zap.Logger

	// Connection pool
	connPool    map[string]*netconfConnection
	connPoolMu  sync.RWMutex
	maxPoolSize int
}

// NetconfConfig contains NETCONF adapter configuration
type NetconfConfig struct {
	Port            int
	Timeout         time.Duration
	KeepaliveInterval time.Duration
	MaxSessions     int
}

// netconfConnection represents a NETCONF session
type netconfConnection struct {
	client    *ssh.Client
	session   *ssh.Session
	stdin     io.WriteCloser
	stdout    io.Reader
	sessionID string
	lastUsed  time.Time
	mu        sync.Mutex
}

// NetconfRPCMessage represents a NETCONF RPC message
type NetconfRPCMessage struct {
	XMLName   xml.Name `xml:"rpc"`
	MessageID string   `xml:"message-id,attr"`
	Namespace string   `xml:"xmlns,attr"`
	Content   string   `xml:",innerxml"`
}

// NetconfRPCReply represents a NETCONF RPC reply
type NetconfRPCReply struct {
	XMLName   xml.Name `xml:"rpc-reply"`
	MessageID string   `xml:"message-id,attr"`
	OK        *struct{} `xml:"ok,omitempty"`
	Data      string   `xml:"data,omitempty"`
	Errors    []NetconfError `xml:"rpc-error,omitempty"`
}

// NetconfError represents a NETCONF error
type NetconfError struct {
	Type     string `xml:"error-type"`
	Tag      string `xml:"error-tag"`
	Severity string `xml:"error-severity"`
	Message  string `xml:"error-message"`
	Path     string `xml:"error-path,omitempty"`
	Info     string `xml:"error-info,omitempty"`
}

// NewNetconfAdapter creates a new NETCONF adapter
func NewNetconfAdapter(config *NetconfConfig, logger *zap.Logger) *NetconfAdapter {
	if config == nil {
		config = &NetconfConfig{
			Port:              netconfDefaultPort,
			Timeout:           30 * time.Second,
			KeepaliveInterval: 60 * time.Second,
			MaxSessions:       10,
		}
	}

	return &NetconfAdapter{
		config:      config,
		logger:      logger,
		connPool:    make(map[string]*netconfConnection),
		maxPoolSize: config.MaxSessions,
	}
}

// Connect establishes a NETCONF session
func (a *NetconfAdapter) Connect(ctx context.Context, target string, creds *Credentials) (Connection, error) {
	// Check pool first
	a.connPoolMu.RLock()
	if conn, exists := a.connPool[target]; exists {
		conn.lastUsed = time.Now()
		a.connPoolMu.RUnlock()
		return &netconfConnectionWrapper{conn: conn, adapter: a, target: target}, nil
	}
	a.connPoolMu.RUnlock()

	// Create new connection
	host, port := a.parseTarget(target)
	if port == "" {
		port = fmt.Sprintf("%d", a.config.Port)
	}

	sshConfig := &ssh.ClientConfig{
		User:            creds.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, use proper host key verification
		Timeout:         a.config.Timeout,
	}

	// Configure authentication
	if creds.Password != "" {
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.Password(creds.Password),
		}
	} else if creds.PrivateKey != nil {
		signer, err := ssh.ParsePrivateKey(creds.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		sshConfig.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	}

	addr := net.JoinHostPort(host, port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Request NETCONF subsystem
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to get stdin: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to get stdout: %w", err)
	}

	if err := session.RequestSubsystem("netconf"); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("failed to request netconf subsystem: %w", err)
	}

	conn := &netconfConnection{
		client:   client,
		session:  session,
		stdin:    stdin,
		stdout:   stdout,
		lastUsed: time.Now(),
	}

	// Exchange hello messages
	if err := a.exchangeHello(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to exchange hello: %w", err)
	}

	// Add to pool
	a.connPoolMu.Lock()
	if len(a.connPool) < a.maxPoolSize {
		a.connPool[target] = conn
	}
	a.connPoolMu.Unlock()

	a.logger.Info("NETCONF session established",
		zap.String("target", target),
		zap.String("session_id", conn.sessionID),
	)

	return &netconfConnectionWrapper{conn: conn, adapter: a, target: target}, nil
}

// exchangeHello exchanges NETCONF hello messages
func (a *NetconfAdapter) exchangeHello(conn *netconfConnection) error {
	// Send hello
	hello := `<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:base:1.1</capability>
  </capabilities>
</hello>` + netconfMessageEnd

	if _, err := conn.stdin.Write([]byte(hello)); err != nil {
		return err
	}

	// Read server hello (simplified)
	buf := make([]byte, 4096)
	n, err := conn.stdout.Read(buf)
	if err != nil {
		return err
	}

	response := string(buf[:n])
	if strings.Contains(response, "<session-id>") {
		start := strings.Index(response, "<session-id>") + 12
		end := strings.Index(response, "</session-id>")
		if start > 12 && end > start {
			conn.sessionID = response[start:end]
		}
	}

	return nil
}

// parseTarget parses target into host and port
func (a *NetconfAdapter) parseTarget(target string) (string, string) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target, ""
	}
	return host, port
}

// Protocol returns the protocol name
func (a *NetconfAdapter) Protocol() string {
	return "netconf"
}

// Close closes all connections in the pool
func (a *NetconfAdapter) Close() error {
	a.connPoolMu.Lock()
	defer a.connPoolMu.Unlock()

	for target, conn := range a.connPool {
		conn.Close()
		delete(a.connPool, target)
	}
	return nil
}

// netconfConnectionWrapper wraps a NETCONF connection
type netconfConnectionWrapper struct {
	conn    *netconfConnection
	adapter *NetconfAdapter
	target  string
}

// Execute executes a NETCONF operation
func (w *netconfConnectionWrapper) Execute(ctx context.Context, operation *Operation) (*OperationResult, error) {
	w.conn.mu.Lock()
	defer w.conn.mu.Unlock()

	startTime := time.Now()

	var rpcContent string
	switch operation.Action {
	case "get":
		rpcContent = w.buildGetRPC(operation)
	case "get-config":
		rpcContent = w.buildGetConfigRPC(operation)
	case "edit-config":
		rpcContent = w.buildEditConfigRPC(operation)
	case "lock":
		rpcContent = w.buildLockRPC(operation)
	case "unlock":
		rpcContent = w.buildUnlockRPC(operation)
	case "commit":
		rpcContent = "<commit/>"
	case "discard-changes":
		rpcContent = "<discard-changes/>"
	default:
		return nil, fmt.Errorf("unsupported NETCONF operation: %s", operation.Action)
	}

	messageID := fmt.Sprintf("%d", time.Now().UnixNano())
	rpc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<rpc message-id="%s" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
%s
</rpc>%s`, messageID, rpcContent, netconfMessageEnd)

	// Send RPC
	if _, err := w.conn.stdin.Write([]byte(rpc)); err != nil {
		return nil, fmt.Errorf("failed to send RPC: %w", err)
	}

	// Read response
	response, err := w.readResponse()
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var reply NetconfRPCReply
	if err := xml.Unmarshal([]byte(response), &reply); err != nil {
		// Return raw response if parsing fails
		return &OperationResult{
			Success:  true,
			Output:   response,
			Duration: time.Since(startTime),
		}, nil
	}

	if len(reply.Errors) > 0 {
		errMsg := reply.Errors[0].Message
		return &OperationResult{
			Success:  false,
			Error:    errMsg,
			Output:   response,
			Duration: time.Since(startTime),
		}, nil
	}

	return &OperationResult{
		Success:  true,
		Output:   reply.Data,
		Duration: time.Since(startTime),
	}, nil
}

// readResponse reads NETCONF response until end marker
func (w *netconfConnectionWrapper) readResponse() (string, error) {
	var response strings.Builder
	buf := make([]byte, 4096)

	for {
		n, err := w.conn.stdout.Read(buf)
		if err != nil && err != io.EOF {
			return "", err
		}
		if n > 0 {
			response.Write(buf[:n])
			if strings.HasSuffix(response.String(), netconfMessageEnd) {
				break
			}
		}
		if err == io.EOF {
			break
		}
	}

	result := response.String()
	return strings.TrimSuffix(result, netconfMessageEnd), nil
}

// buildGetRPC builds a get RPC
func (w *netconfConnectionWrapper) buildGetRPC(op *Operation) string {
	if filter, ok := op.Parameters["filter"].(string); ok && filter != "" {
		return fmt.Sprintf(`<get><filter type="subtree">%s</filter></get>`, filter)
	}
	return "<get/>"
}

// buildGetConfigRPC builds a get-config RPC
func (w *netconfConnectionWrapper) buildGetConfigRPC(op *Operation) string {
	source := "running"
	if s, ok := op.Parameters["source"].(string); ok {
		source = s
	}

	rpc := fmt.Sprintf(`<get-config><source><%s/></source>`, source)
	if filter, ok := op.Parameters["filter"].(string); ok && filter != "" {
		rpc += fmt.Sprintf(`<filter type="subtree">%s</filter>`, filter)
	}
	rpc += "</get-config>"
	return rpc
}

// buildEditConfigRPC builds an edit-config RPC
func (w *netconfConnectionWrapper) buildEditConfigRPC(op *Operation) string {
	target := "candidate"
	if t, ok := op.Parameters["target"].(string); ok {
		target = t
	}

	config := ""
	if c, ok := op.Parameters["config"].(string); ok {
		config = c
	}

	operation := "merge"
	if o, ok := op.Parameters["default_operation"].(string); ok {
		operation = o
	}

	return fmt.Sprintf(`<edit-config>
  <target><%s/></target>
  <default-operation>%s</default-operation>
  <config>%s</config>
</edit-config>`, target, operation, config)
}

// buildLockRPC builds a lock RPC
func (w *netconfConnectionWrapper) buildLockRPC(op *Operation) string {
	target := "candidate"
	if t, ok := op.Parameters["target"].(string); ok {
		target = t
	}
	return fmt.Sprintf(`<lock><target><%s/></target></lock>`, target)
}

// buildUnlockRPC builds an unlock RPC
func (w *netconfConnectionWrapper) buildUnlockRPC(op *Operation) string {
	target := "candidate"
	if t, ok := op.Parameters["target"].(string); ok {
		target = t
	}
	return fmt.Sprintf(`<unlock><target><%s/></target></unlock>`, target)
}

// Close closes the connection
func (w *netconfConnectionWrapper) Close() error {
	// Don't close pooled connections
	return nil
}

// Close closes the NETCONF session
func (c *netconfConnection) Close() error {
	if c.session != nil {
		c.session.Close()
	}
	if c.client != nil {
		c.client.Close()
	}
	return nil
}

var (
	ErrNetconfRPCError = errors.New("NETCONF RPC error")
)
