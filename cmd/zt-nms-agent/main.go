package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Agent represents the ZT-NMS device agent
type Agent struct {
	deviceID   uuid.UUID
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	serverURL  string
	logger     *zap.Logger
	client     *http.Client
	
	// State
	registered   bool
	attestedAt   time.Time
	configHash   []byte
	
	// Channels
	stopCh       chan struct{}
}

// AgentConfig contains agent configuration
type AgentConfig struct {
	DeviceID   string `mapstructure:"device_id"`
	ServerURL  string `mapstructure:"server_url"`
	PrivateKey string `mapstructure:"private_key"`
	
	AttestationInterval time.Duration `mapstructure:"attestation_interval"`
	HeartbeatInterval   time.Duration `mapstructure:"heartbeat_interval"`
	ConfigCheckInterval time.Duration `mapstructure:"config_check_interval"`
	
	TLS struct {
		CertFile string `mapstructure:"cert_file"`
		KeyFile  string `mapstructure:"key_file"`
		CAFile   string `mapstructure:"ca_file"`
	} `mapstructure:"tls"`
}

func main() {
	// Initialize logger
	logger := initLogger()
	defer logger.Sync()

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Create agent
	agent, err := NewAgent(config, logger)
	if err != nil {
		logger.Fatal("Failed to create agent", zap.Error(err))
	}

	// Start agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		logger.Fatal("Failed to start agent", zap.Error(err))
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutting down agent...")
	agent.Stop()
}

// NewAgent creates a new agent instance
func NewAgent(config *AgentConfig, logger *zap.Logger) (*Agent, error) {
	// Parse device ID
	var deviceID uuid.UUID
	if config.DeviceID != "" {
		var err error
		deviceID, err = uuid.Parse(config.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("invalid device ID: %w", err)
		}
	} else {
		deviceID = uuid.New()
	}

	// Load or generate key pair
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey

	if config.PrivateKey != "" {
		keyBytes, err := hex.DecodeString(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
		privateKey = ed25519.PrivateKey(keyBytes)
		publicKey = privateKey.Public().(ed25519.PublicKey)
	} else {
		var err error
		publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		logger.Info("Generated new key pair",
			zap.String("public_key", hex.EncodeToString(publicKey)))
	}

	return &Agent{
		deviceID:   deviceID,
		privateKey: privateKey,
		publicKey:  publicKey,
		serverURL:  config.ServerURL,
		logger:     logger,
		client:     &http.Client{Timeout: 30 * time.Second},
		stopCh:     make(chan struct{}),
	}, nil
}

// Start starts the agent
func (a *Agent) Start(ctx context.Context) error {
	a.logger.Info("Starting ZT-NMS agent",
		zap.String("device_id", a.deviceID.String()),
		zap.String("server", a.serverURL),
	)

	// Register with server
	if err := a.register(ctx); err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Initial attestation
	if err := a.attest(ctx); err != nil {
		a.logger.Warn("Initial attestation failed", zap.Error(err))
	}

	// Start background tasks
	go a.heartbeatLoop(ctx)
	go a.attestationLoop(ctx)
	go a.configCheckLoop(ctx)

	return nil
}

// Stop stops the agent
func (a *Agent) Stop() {
	close(a.stopCh)
}

// register registers the device with the server
func (a *Agent) register(ctx context.Context) error {
	hostname, _ := os.Hostname()
	
	req := map[string]interface{}{
		"type": "device",
		"attributes": map[string]interface{}{
			"hostname":      hostname,
			"vendor":        runtime.GOOS,
			"model":         runtime.GOARCH,
			"os_type":       runtime.GOOS,
			"os_version":    runtime.Version(),
			"management_ip": a.getLocalIP(),
			"role":          "managed-device",
		},
		"public_key": hex.EncodeToString(a.publicKey),
	}

	reqJSON, _ := json.Marshal(req)
	
	resp, err := a.doRequest(ctx, "POST", "/api/v1/identities", reqJSON)
	if err != nil {
		// Device might already be registered
		a.logger.Debug("Registration response", zap.Error(err))
	} else {
		a.logger.Info("Device registered successfully")
		_ = resp
	}

	a.registered = true
	return nil
}

// attest performs device attestation
func (a *Agent) attest(ctx context.Context) error {
	a.logger.Debug("Performing attestation")

	// Collect measurements
	measurements := a.collectMeasurements()

	// Generate nonce
	nonce := make([]byte, 32)
	rand.Read(nonce)

	// Create attestation report
	report := map[string]interface{}{
		"device_id":    a.deviceID.String(),
		"timestamp":    time.Now().UTC(),
		"type":         "software",
		"measurements": measurements,
		"nonce":        hex.EncodeToString(nonce),
	}

	// Sign report
	reportJSON, _ := json.Marshal(report)
	signature := ed25519.Sign(a.privateKey, reportJSON)
	report["software_signature"] = hex.EncodeToString(signature)

	// Send to server
	reqJSON, _ := json.Marshal(report)
	_, err := a.doRequest(ctx, "POST", "/api/v1/devices/"+a.deviceID.String()+"/attestation", reqJSON)
	if err != nil {
		return err
	}

	a.attestedAt = time.Now()
	a.logger.Info("Attestation completed successfully")
	return nil
}

// collectMeasurements collects device measurements
func (a *Agent) collectMeasurements() map[string]interface{} {
	measurements := make(map[string]interface{})

	// OS hash (simplified - hash of version string)
	osInfo := fmt.Sprintf("%s-%s-%s", runtime.GOOS, runtime.GOARCH, runtime.Version())
	osHash := sha256.Sum256([]byte(osInfo))
	measurements["os_hash"] = hex.EncodeToString(osHash[:])

	// Agent hash (hash of self)
	if execPath, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(execPath); err == nil {
			agentHash := sha256.Sum256(data)
			measurements["agent_hash"] = hex.EncodeToString(agentHash[:])
		}
	}

	// Running config hash
	if a.configHash != nil {
		measurements["running_config_hash"] = hex.EncodeToString(a.configHash)
	}

	// Open ports (Linux-specific)
	if runtime.GOOS == "linux" {
		measurements["open_ports"] = a.getOpenPorts()
	}

	// Active processes (simplified)
	measurements["active_processes"] = a.getActiveProcesses()

	return measurements
}

// getLocalIP returns the local IP address
func (a *Agent) getLocalIP() string {
	// Simplified - in production, use proper network interface detection
	return "127.0.0.1"
}

// getOpenPorts returns open ports (Linux)
func (a *Agent) getOpenPorts() []map[string]interface{} {
	var ports []map[string]interface{}

	// Read from /proc/net/tcp and /proc/net/udp
	// Simplified implementation
	cmd := exec.Command("ss", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		return ports
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			local := fields[4]
			parts := strings.Split(local, ":")
			if len(parts) >= 2 {
				ports = append(ports, map[string]interface{}{
					"port":     parts[len(parts)-1],
					"protocol": fields[0],
				})
			}
		}
	}

	return ports
}

// getActiveProcesses returns active processes
func (a *Agent) getActiveProcesses() []map[string]interface{} {
	var processes []map[string]interface{}

	// Simplified - just get a few key processes
	cmd := exec.Command("ps", "-eo", "pid,comm")
	output, err := cmd.Output()
	if err != nil {
		return processes
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			processes = append(processes, map[string]interface{}{
				"pid":  fields[0],
				"name": fields[1],
			})
		}
	}

	// Limit to first 50
	if len(processes) > 50 {
		processes = processes[:50]
	}

	return processes
}

// heartbeatLoop sends periodic heartbeats
func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.sendHeartbeat(ctx)
		}
	}
}

// sendHeartbeat sends a heartbeat to the server
func (a *Agent) sendHeartbeat(ctx context.Context) {
	heartbeat := map[string]interface{}{
		"device_id":  a.deviceID.String(),
		"timestamp":  time.Now().UTC(),
		"status":     "online",
		"attested":   !a.attestedAt.IsZero(),
		"attested_at": a.attestedAt,
	}

	reqJSON, _ := json.Marshal(heartbeat)
	_, err := a.doRequest(ctx, "POST", "/api/v1/devices/"+a.deviceID.String()+"/heartbeat", reqJSON)
	if err != nil {
		a.logger.Debug("Heartbeat failed", zap.Error(err))
	}
}

// attestationLoop performs periodic attestation
func (a *Agent) attestationLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			if err := a.attest(ctx); err != nil {
				a.logger.Warn("Periodic attestation failed", zap.Error(err))
			}
		}
	}
}

// configCheckLoop checks for configuration updates
func (a *Agent) configCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.checkConfig(ctx)
		}
	}
}

// checkConfig checks for pending configuration
func (a *Agent) checkConfig(ctx context.Context) {
	resp, err := a.doRequest(ctx, "GET", "/api/v1/devices/"+a.deviceID.String()+"/config/pending", nil)
	if err != nil {
		a.logger.Debug("Config check failed", zap.Error(err))
		return
	}

	var config struct {
		HasPending bool   `json:"has_pending"`
		BlockID    string `json:"block_id"`
	}
	if err := json.Unmarshal(resp, &config); err != nil {
		return
	}

	if config.HasPending {
		a.logger.Info("Pending configuration found", zap.String("block_id", config.BlockID))
		// In production, would apply the configuration here
	}
}

// doRequest performs an authenticated HTTP request
func (a *Agent) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.serverURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-ID", a.deviceID.String())
	
	// Sign request for authentication
	timestamp := time.Now().UTC().Format(time.RFC3339)
	message := fmt.Sprintf("%s:%s:%s", method, path, timestamp)
	signature := ed25519.Sign(a.privateKey, []byte(message))
	
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", hex.EncodeToString(signature))
	req.Header.Set("X-Public-Key", hex.EncodeToString(a.publicKey))

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func initLogger() *zap.Logger {
	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapcore.InfoLevel),
		Development: false,
		Encoding:    "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.MillisDurationEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	return logger
}

func loadConfig() (*AgentConfig, error) {
	viper.SetConfigName("agent")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/zt-nms/")
	viper.AddConfigPath("$HOME/.zt-nms/")
	viper.AddConfigPath(".")

	viper.SetDefault("server_url", "https://localhost:8443")
	viper.SetDefault("attestation_interval", "1h")
	viper.SetDefault("heartbeat_interval", "30s")
	viper.SetDefault("config_check_interval", "5m")

	viper.AutomaticEnv()
	viper.SetEnvPrefix("ZTNMS_AGENT")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var config AgentConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
