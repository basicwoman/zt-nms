package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/basicwoman/zt-nms/pkg/models"
)

// SSHAdapter implements ProtocolAdapter for SSH connections
type SSHAdapter struct {
	mu          sync.RWMutex
	connections map[string]*sshConnection
	config      *SSHAdapterConfig
}

// SSHAdapterConfig contains SSH adapter configuration
type SSHAdapterConfig struct {
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	MaxOutputSize  int
	KexAlgorithms  []string
	Ciphers        []string
	MACs           []string
}

type sshConnection struct {
	client    *ssh.Client
	device    *models.Device
	createdAt time.Time
	lastUsed  time.Time
}

// DefaultSSHConfig returns default SSH configuration
func DefaultSSHConfig() *SSHAdapterConfig {
	return &SSHAdapterConfig{
		ConnectTimeout: 30 * time.Second,
		CommandTimeout: 60 * time.Second,
		MaxOutputSize:  10 * 1024 * 1024, // 10MB
		KexAlgorithms: []string{
			"curve25519-sha256",
			"curve25519-sha256@libssh.org",
			"ecdh-sha2-nistp256",
			"ecdh-sha2-nistp384",
			"ecdh-sha2-nistp521",
			"diffie-hellman-group14-sha256",
		},
		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-ctr",
			"aes192-ctr",
			"aes128-ctr",
		},
		MACs: []string{
			"hmac-sha2-256-etm@openssh.com",
			"hmac-sha2-512-etm@openssh.com",
			"hmac-sha2-256",
			"hmac-sha2-512",
		},
	}
}

// NewSSHAdapter creates a new SSH adapter
func NewSSHAdapter(config *SSHAdapterConfig) *SSHAdapter {
	if config == nil {
		config = DefaultSSHConfig()
	}
	return &SSHAdapter{
		connections: make(map[string]*sshConnection),
		config:      config,
	}
}

// Connect establishes an SSH connection to a device
func (a *SSHAdapter) Connect(ctx context.Context, device *models.Device, credentials []byte) error {
	// Parse credentials (JSON: {"username": "...", "password": "...", "private_key": "..."})
	creds, err := parseSSHCredentials(credentials)
	if err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}

	// Build SSH config
	sshConfig := &ssh.ClientConfig{
		User:            creds.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, use proper host key verification
		Timeout:         a.config.ConnectTimeout,
		Config: ssh.Config{
			KeyExchanges: a.config.KexAlgorithms,
			Ciphers:      a.config.Ciphers,
			MACs:         a.config.MACs,
		},
	}

	// Set up authentication methods
	var authMethods []ssh.AuthMethod
	if creds.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(creds.PrivateKey))
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if creds.Password != "" {
		authMethods = append(authMethods, ssh.Password(creds.Password))
	}
	sshConfig.Auth = authMethods

	// Determine address
	addr := device.ManagementIP
	port := device.ManagementPort
	if port == 0 {
		port = 22
	}
	address := fmt.Sprintf("%s:%d", addr, port)

	// Connect with context
	var conn net.Conn
	dialer := &net.Dialer{Timeout: a.config.ConnectTimeout}
	conn, err = dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Create SSH connection
	c, chans, reqs, err := ssh.NewClientConn(conn, address, sshConfig)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to establish SSH connection: %w", err)
	}

	client := ssh.NewClient(c, chans, reqs)

	// Store connection
	a.mu.Lock()
	a.connections[device.ID.String()] = &sshConnection{
		client:    client,
		device:    device,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}
	a.mu.Unlock()

	return nil
}

// Disconnect closes an SSH connection
func (a *SSHAdapter) Disconnect(ctx context.Context, device *models.Device) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	conn, exists := a.connections[device.ID.String()]
	if !exists {
		return nil
	}

	delete(a.connections, device.ID.String())
	return conn.client.Close()
}

// Execute runs a command on the device
func (a *SSHAdapter) Execute(ctx context.Context, device *models.Device, command string) (*ExecutionResult, error) {
	conn := a.getConnection(device)
	if conn == nil {
		return nil, fmt.Errorf("device not connected")
	}

	// Create session
	session, err := conn.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up output capture
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Execute with timeout
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	var execErr error
	select {
	case err := <-done:
		execErr = err
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return nil, ctx.Err()
	case <-time.After(a.config.CommandTimeout):
		session.Signal(ssh.SIGKILL)
		return nil, fmt.Errorf("command timed out")
	}

	duration := time.Since(start)

	// Update last used
	a.mu.Lock()
	conn.lastUsed = time.Now()
	a.mu.Unlock()

	result := &ExecutionResult{
		Output:   stdout.String(),
		Duration: duration,
	}

	if execErr != nil {
		result.Error = execErr.Error()
		if exitErr, ok := execErr.(*ssh.ExitError); ok {
			result.ExitCode = exitErr.ExitStatus()
		}
		if stderr.Len() > 0 {
			result.Error = stderr.String()
		}
	}

	// Check output size
	if len(result.Output) > a.config.MaxOutputSize {
		result.Output = result.Output[:a.config.MaxOutputSize]
		result.Truncated = true
	}

	return result, nil
}

// GetConfig retrieves configuration from the device
func (a *SSHAdapter) GetConfig(ctx context.Context, device *models.Device, section string) (string, error) {
	// Determine command based on device type and section
	command := a.getConfigCommand(device, section)
	
	result, err := a.Execute(ctx, device, command)
	if err != nil {
		return "", err
	}

	if result.Error != "" && result.ExitCode != 0 {
		return "", fmt.Errorf("command failed: %s", result.Error)
	}

	return result.Output, nil
}

// SetConfig applies configuration commands to the device
func (a *SSHAdapter) SetConfig(ctx context.Context, device *models.Device, commands []string) error {
	conn := a.getConnection(device)
	if conn == nil {
		return fmt.Errorf("device not connected")
	}

	// For most network devices, we need to enter config mode
	// and execute commands in sequence
	session, err := conn.client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up PTY for interactive session
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return fmt.Errorf("failed to request PTY: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout: %w", err)
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Wait for prompt and execute commands
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				if err != io.EOF {
					// Log error
				}
				return
			}
			_ = buf[:n] // Process output
		}
	}()

	// Enter configuration mode (vendor-specific)
	configCommands := a.buildConfigSequence(device, commands)
	for _, cmd := range configCommands {
		_, err := fmt.Fprintf(stdin, "%s\n", cmd)
		if err != nil {
			return fmt.Errorf("failed to send command: %w", err)
		}
		time.Sleep(100 * time.Millisecond) // Wait for command processing
	}

	// Exit configuration mode
	fmt.Fprintf(stdin, "exit\n")
	time.Sleep(100 * time.Millisecond)

	return nil
}

// IsConnected checks if a device is connected
func (a *SSHAdapter) IsConnected(device *models.Device) bool {
	return a.getConnection(device) != nil
}

// getConnection retrieves an existing connection
func (a *SSHAdapter) getConnection(device *models.Device) *sshConnection {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.connections[device.ID.String()]
}

// getConfigCommand returns the appropriate show config command for the device
func (a *SSHAdapter) getConfigCommand(device *models.Device, section string) string {
	osType := device.OSType

	switch section {
	case "running-config", "running":
		switch osType {
		case "ios", "ios-xe", "nx-os":
			return "show running-config"
		case "junos":
			return "show configuration"
		case "eos":
			return "show running-config"
		case "fortios":
			return "show full-configuration"
		default:
			return "show running-config"
		}
	case "startup-config", "startup":
		switch osType {
		case "ios", "ios-xe", "nx-os":
			return "show startup-config"
		case "junos":
			return "show configuration | display set"
		case "eos":
			return "show startup-config"
		default:
			return "show startup-config"
		}
	case "interfaces":
		switch osType {
		case "ios", "ios-xe":
			return "show ip interface brief"
		case "junos":
			return "show interfaces terse"
		case "nx-os":
			return "show interface brief"
		default:
			return "show interfaces"
		}
	case "routes", "routing":
		switch osType {
		case "ios", "ios-xe":
			return "show ip route"
		case "junos":
			return "show route"
		case "nx-os":
			return "show ip route"
		default:
			return "show ip route"
		}
	case "bgp":
		switch osType {
		case "ios", "ios-xe":
			return "show ip bgp summary"
		case "junos":
			return "show bgp summary"
		case "nx-os":
			return "show bgp all summary"
		default:
			return "show bgp summary"
		}
	default:
		return fmt.Sprintf("show %s", section)
	}
}

// buildConfigSequence builds a sequence of commands for configuration
func (a *SSHAdapter) buildConfigSequence(device *models.Device, commands []string) []string {
	osType := device.OSType
	var sequence []string

	switch osType {
	case "ios", "ios-xe":
		sequence = append(sequence, "configure terminal")
		sequence = append(sequence, commands...)
		sequence = append(sequence, "end")
	case "junos":
		sequence = append(sequence, "configure")
		sequence = append(sequence, commands...)
		sequence = append(sequence, "commit")
		sequence = append(sequence, "exit")
	case "nx-os":
		sequence = append(sequence, "configure terminal")
		sequence = append(sequence, commands...)
		sequence = append(sequence, "end")
	case "eos":
		sequence = append(sequence, "configure terminal")
		sequence = append(sequence, commands...)
		sequence = append(sequence, "end")
	default:
		sequence = commands
	}

	return sequence
}

// sshCredentials represents SSH credentials
type sshCredentials struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

// parseSSHCredentials parses SSH credentials from JSON
func parseSSHCredentials(data []byte) (*sshCredentials, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty credentials")
	}

	var creds sshCredentials
	// Simple parsing - in production use proper JSON parsing
	// For now, assume format: username:password or username:key
	parts := bytes.SplitN(data, []byte(":"), 2)
	if len(parts) >= 1 {
		creds.Username = string(parts[0])
	}
	if len(parts) >= 2 {
		if bytes.HasPrefix(parts[1], []byte("-----BEGIN")) {
			creds.PrivateKey = string(parts[1])
		} else {
			creds.Password = string(parts[1])
		}
	}

	if creds.Username == "" {
		return nil, fmt.Errorf("username required")
	}
	if creds.Password == "" && creds.PrivateKey == "" {
		return nil, fmt.Errorf("password or private key required")
	}

	return &creds, nil
}

// CleanupIdleConnections closes idle connections
func (a *SSHAdapter) CleanupIdleConnections(maxIdleTime time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for id, conn := range a.connections {
		if now.Sub(conn.lastUsed) > maxIdleTime {
			conn.client.Close()
			delete(a.connections, id)
		}
	}
}
