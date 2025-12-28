package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	restconfDefaultPort     = 443
	restconfDataPath        = "/restconf/data"
	restconfOperationsPath  = "/restconf/operations"
	contentTypeJSON         = "application/yang-data+json"
	contentTypeXML          = "application/yang-data+xml"
)

// RestconfAdapter implements the ProtocolAdapter interface for RESTCONF
type RestconfAdapter struct {
	config     *RestconfConfig
	logger     *zap.Logger
	httpClient *http.Client

	// Connection pool (HTTP clients per target)
	clientPool   map[string]*http.Client
	clientPoolMu sync.RWMutex
}

// RestconfConfig contains RESTCONF adapter configuration
type RestconfConfig struct {
	Port              int
	Timeout           time.Duration
	TLSSkipVerify     bool
	MaxIdleConns      int
	IdleConnTimeout   time.Duration
	UseHTTPS          bool
	ContentType       string // json or xml
}

// NewRestconfAdapter creates a new RESTCONF adapter
func NewRestconfAdapter(config *RestconfConfig, logger *zap.Logger) *RestconfAdapter {
	if config == nil {
		config = &RestconfConfig{
			Port:            restconfDefaultPort,
			Timeout:         30 * time.Second,
			TLSSkipVerify:   false,
			MaxIdleConns:    10,
			IdleConnTimeout: 90 * time.Second,
			UseHTTPS:        true,
			ContentType:     "json",
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify,
		},
		MaxIdleConns:        config.MaxIdleConns,
		IdleConnTimeout:     config.IdleConnTimeout,
		DisableCompression:  false,
		DisableKeepAlives:   false,
	}

	return &RestconfAdapter{
		config: config,
		logger: logger,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		},
		clientPool: make(map[string]*http.Client),
	}
}

// Connect establishes a RESTCONF connection
func (a *RestconfAdapter) Connect(ctx context.Context, target string, creds *Credentials) (Connection, error) {
	// Parse target
	host, port := a.parseTarget(target)
	if port == "" {
		port = fmt.Sprintf("%d", a.config.Port)
	}

	// Build base URL
	scheme := "https"
	if !a.config.UseHTTPS {
		scheme = "http"
	}
	baseURL := fmt.Sprintf("%s://%s:%s", scheme, host, port)

	// Create connection wrapper
	conn := &restconfConnectionWrapper{
		adapter:     a,
		target:      target,
		baseURL:     baseURL,
		credentials: creds,
		contentType: a.getContentType(),
	}

	// Test connection by fetching root resource
	if err := conn.testConnection(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", baseURL, err)
	}

	a.logger.Info("RESTCONF connection established",
		zap.String("target", target),
		zap.String("base_url", baseURL),
	)

	return conn, nil
}

// parseTarget parses target into host and port
func (a *RestconfAdapter) parseTarget(target string) (string, string) {
	// Check if it's already a URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err == nil {
			return u.Hostname(), u.Port()
		}
	}

	// Try to split host:port
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		return target[:idx], target[idx+1:]
	}
	return target, ""
}

// getContentType returns the content type based on configuration
func (a *RestconfAdapter) getContentType() string {
	if a.config.ContentType == "xml" {
		return contentTypeXML
	}
	return contentTypeJSON
}

// Protocol returns the protocol name
func (a *RestconfAdapter) Protocol() string {
	return "restconf"
}

// Close closes all connections
func (a *RestconfAdapter) Close() error {
	a.clientPoolMu.Lock()
	defer a.clientPoolMu.Unlock()

	for target := range a.clientPool {
		delete(a.clientPool, target)
	}
	return nil
}

// restconfConnectionWrapper wraps a RESTCONF connection
type restconfConnectionWrapper struct {
	adapter     *RestconfAdapter
	target      string
	baseURL     string
	credentials *Credentials
	contentType string
}

// testConnection tests the RESTCONF connection
func (w *restconfConnectionWrapper) testConnection(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", w.baseURL+"/restconf", nil)
	if err != nil {
		return err
	}

	w.setHeaders(req)
	w.setAuth(req)

	resp, err := w.adapter.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("RESTCONF error: %d - %s", resp.StatusCode, string(body))
	}

	return nil
}

// Execute executes a RESTCONF operation
func (w *restconfConnectionWrapper) Execute(ctx context.Context, operation *Operation) (*OperationResult, error) {
	startTime := time.Now()

	var method, path string
	var body io.Reader

	switch operation.Action {
	case "get":
		method = "GET"
		path = w.buildDataPath(operation)
	case "get-config":
		method = "GET"
		path = w.buildDataPath(operation)
	case "edit-config":
		method = w.getEditMethod(operation)
		path = w.buildDataPath(operation)
		body = w.buildRequestBody(operation)
	case "create":
		method = "POST"
		path = w.buildDataPath(operation)
		body = w.buildRequestBody(operation)
	case "replace":
		method = "PUT"
		path = w.buildDataPath(operation)
		body = w.buildRequestBody(operation)
	case "delete":
		method = "DELETE"
		path = w.buildDataPath(operation)
	case "rpc":
		method = "POST"
		path = w.buildOperationsPath(operation)
		body = w.buildRequestBody(operation)
	default:
		return nil, fmt.Errorf("unsupported RESTCONF operation: %s", operation.Action)
	}

	// Create request
	reqURL := w.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	w.setHeaders(req)
	w.setAuth(req)

	// Add query parameters if present
	if params, ok := operation.Parameters["query"].(map[string]interface{}); ok {
		q := req.URL.Query()
		for k, v := range params {
			q.Add(k, fmt.Sprintf("%v", v))
		}
		req.URL.RawQuery = q.Encode()
	}

	// Execute request
	resp, err := w.adapter.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	duration := time.Since(startTime)

	// Check for errors
	if resp.StatusCode >= 400 {
		errorMsg := w.parseErrorResponse(respBody)
		return &OperationResult{
			Success:  false,
			Error:    errorMsg,
			Output:   string(respBody),
			Duration: duration,
		}, nil
	}

	return &OperationResult{
		Success:  true,
		Output:   string(respBody),
		Duration: duration,
	}, nil
}

// buildDataPath builds the RESTCONF data path
func (w *restconfConnectionWrapper) buildDataPath(op *Operation) string {
	path := restconfDataPath

	// Add resource path
	if resource, ok := op.Parameters["path"].(string); ok && resource != "" {
		if !strings.HasPrefix(resource, "/") {
			path += "/"
		}
		path += resource
	}

	return path
}

// buildOperationsPath builds the RESTCONF operations path
func (w *restconfConnectionWrapper) buildOperationsPath(op *Operation) string {
	path := restconfOperationsPath

	// Add RPC name
	if rpcName, ok := op.Parameters["rpc"].(string); ok && rpcName != "" {
		if !strings.HasPrefix(rpcName, "/") {
			path += "/"
		}
		path += rpcName
	}

	return path
}

// getEditMethod returns the HTTP method for edit-config
func (w *restconfConnectionWrapper) getEditMethod(op *Operation) string {
	if method, ok := op.Parameters["method"].(string); ok {
		return strings.ToUpper(method)
	}
	// Default to PATCH for edit-config
	return "PATCH"
}

// buildRequestBody builds the request body
func (w *restconfConnectionWrapper) buildRequestBody(op *Operation) io.Reader {
	if data, ok := op.Parameters["data"]; ok {
		switch v := data.(type) {
		case string:
			return strings.NewReader(v)
		case []byte:
			return bytes.NewReader(v)
		default:
			// Marshal to JSON
			jsonData, err := json.Marshal(v)
			if err != nil {
				return nil
			}
			return bytes.NewReader(jsonData)
		}
	}
	return nil
}

// setHeaders sets common headers
func (w *restconfConnectionWrapper) setHeaders(req *http.Request) {
	req.Header.Set("Accept", w.contentType)
	if req.Method != "GET" && req.Method != "DELETE" {
		req.Header.Set("Content-Type", w.contentType)
	}
}

// setAuth sets authentication
func (w *restconfConnectionWrapper) setAuth(req *http.Request) {
	if w.credentials == nil {
		return
	}

	if w.credentials.Username != "" && w.credentials.Password != "" {
		req.SetBasicAuth(w.credentials.Username, w.credentials.Password)
	}

	if w.credentials.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.credentials.Token)
	}
}

// parseErrorResponse parses RESTCONF error response
func (w *restconfConnectionWrapper) parseErrorResponse(body []byte) string {
	// Try to parse JSON error
	var errResp struct {
		Errors struct {
			Error []struct {
				ErrorType    string `json:"error-type"`
				ErrorTag     string `json:"error-tag"`
				ErrorMessage string `json:"error-message"`
			} `json:"error"`
		} `json:"ietf-restconf:errors"`
	}

	if err := json.Unmarshal(body, &errResp); err == nil && len(errResp.Errors.Error) > 0 {
		e := errResp.Errors.Error[0]
		return fmt.Sprintf("%s: %s - %s", e.ErrorType, e.ErrorTag, e.ErrorMessage)
	}

	// Return raw body if parsing fails
	if len(body) > 200 {
		return string(body[:200]) + "..."
	}
	return string(body)
}

// Close closes the connection
func (w *restconfConnectionWrapper) Close() error {
	// HTTP connections are pooled, nothing to close
	return nil
}

// RestconfClient provides a high-level RESTCONF client
type RestconfClient struct {
	conn     Connection
	basePath string
}

// NewRestconfClient creates a new RESTCONF client
func NewRestconfClient(conn Connection, basePath string) *RestconfClient {
	return &RestconfClient{
		conn:     conn,
		basePath: basePath,
	}
}

// Get retrieves data from the specified path
func (c *RestconfClient) Get(ctx context.Context, path string) (string, error) {
	op := &Operation{
		Action: "get",
		Parameters: map[string]interface{}{
			"path": c.basePath + path,
		},
	}

	result, err := c.conn.Execute(ctx, op)
	if err != nil {
		return "", err
	}

	if !result.Success {
		return "", fmt.Errorf("GET failed: %s", result.Error)
	}

	return result.Output, nil
}

// Put replaces data at the specified path
func (c *RestconfClient) Put(ctx context.Context, path string, data interface{}) error {
	op := &Operation{
		Action: "replace",
		Parameters: map[string]interface{}{
			"path": c.basePath + path,
			"data": data,
		},
	}

	result, err := c.conn.Execute(ctx, op)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("PUT failed: %s", result.Error)
	}

	return nil
}

// Patch modifies data at the specified path
func (c *RestconfClient) Patch(ctx context.Context, path string, data interface{}) error {
	op := &Operation{
		Action: "edit-config",
		Parameters: map[string]interface{}{
			"path":   c.basePath + path,
			"data":   data,
			"method": "PATCH",
		},
	}

	result, err := c.conn.Execute(ctx, op)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("PATCH failed: %s", result.Error)
	}

	return nil
}

// Post creates data at the specified path
func (c *RestconfClient) Post(ctx context.Context, path string, data interface{}) error {
	op := &Operation{
		Action: "create",
		Parameters: map[string]interface{}{
			"path": c.basePath + path,
			"data": data,
		},
	}

	result, err := c.conn.Execute(ctx, op)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("POST failed: %s", result.Error)
	}

	return nil
}

// Delete removes data at the specified path
func (c *RestconfClient) Delete(ctx context.Context, path string) error {
	op := &Operation{
		Action: "delete",
		Parameters: map[string]interface{}{
			"path": c.basePath + path,
		},
	}

	result, err := c.conn.Execute(ctx, op)
	if err != nil {
		return err
	}

	if !result.Success {
		return fmt.Errorf("DELETE failed: %s", result.Error)
	}

	return nil
}

// RPC invokes a RESTCONF RPC operation
func (c *RestconfClient) RPC(ctx context.Context, rpcName string, input interface{}) (string, error) {
	op := &Operation{
		Action: "rpc",
		Parameters: map[string]interface{}{
			"rpc":  rpcName,
			"data": input,
		},
	}

	result, err := c.conn.Execute(ctx, op)
	if err != nil {
		return "", err
	}

	if !result.Success {
		return "", fmt.Errorf("RPC failed: %s", result.Error)
	}

	return result.Output, nil
}
