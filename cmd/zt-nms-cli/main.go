package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	apiURL     string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	verbose    bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "zt-nms-cli",
		Short: "Zero Trust NMS Command Line Interface",
		Long: `Zero Trust Network Management System CLI
		
A command-line interface for managing network devices 
with zero-trust security model.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			loadConfig()
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "https://localhost:8443", "API server URL")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Add commands
	rootCmd.AddCommand(authCmd())
	rootCmd.AddCommand(identityCmd())
	rootCmd.AddCommand(deviceCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(policyCmd())
	rootCmd.AddCommand(capabilityCmd())
	rootCmd.AddCommand(auditCmd())
	rootCmd.AddCommand(keygenCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func loadConfig() {
	viper.SetConfigName("zt-nms-cli")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$HOME/.zt-nms")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err == nil {
		apiURL = viper.GetString("api_url")
		
		// Load private key
		keyPath := viper.GetString("private_key_path")
		if keyPath != "" {
			data, err := os.ReadFile(keyPath)
			if err == nil {
				privateKey = ed25519.PrivateKey(data)
				publicKey = privateKey.Public().(ed25519.PublicKey)
			}
		}
	}
}

// Auth commands
func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "login",
		Short: "Authenticate with the server",
		RunE:  authLogin,
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Check authentication status",
		RunE:  authStatus,
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "logout",
		Short: "Logout and clear credentials",
		RunE:  authLogout,
	})

	return cmd
}

func authLogin(cmd *cobra.Command, args []string) error {
	if privateKey == nil {
		return fmt.Errorf("private key not configured. Run 'zt-nms-cli keygen' first")
	}

	// Get challenge
	resp, err := http.Post(apiURL+"/api/v1/auth/challenge", "application/json", nil)
	if err != nil {
		return fmt.Errorf("failed to get challenge: %w", err)
	}
	defer resp.Body.Close()

	var challengeResp struct {
		Challenge string    `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&challengeResp); err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}

	// Sign challenge
	challengeBytes, _ := base64.StdEncoding.DecodeString(challengeResp.Challenge)
	signature := ed25519.Sign(privateKey, challengeBytes)

	// Authenticate
	authReq := map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(publicKey),
		"challenge":  challengeResp.Challenge,
		"signature":  base64.StdEncoding.EncodeToString(signature),
	}
	authJSON, _ := json.Marshal(authReq)

	resp, err = http.Post(apiURL+"/api/v1/auth/authenticate", "application/json", strings.NewReader(string(authJSON)))
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed: %s", string(body))
	}

	var authResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Save token
	viper.Set("access_token", authResp.AccessToken)
	viper.Set("token_expires", time.Now().Add(time.Duration(authResp.ExpiresIn)*time.Second))
	
	configPath := os.ExpandEnv("$HOME/.zt-nms/zt-nms-cli.yaml")
	if err := viper.WriteConfigAs(configPath); err != nil {
		fmt.Printf("Warning: Could not save token: %v\n", err)
	}

	fmt.Println("Successfully authenticated")
	return nil
}

func authStatus(cmd *cobra.Command, args []string) error {
	token := viper.GetString("access_token")
	if token == "" {
		fmt.Println("Not authenticated")
		return nil
	}
	expires := viper.GetTime("token_expires")
	if time.Now().After(expires) {
		fmt.Println("Token expired")
		return nil
	}
	fmt.Printf("Authenticated (expires: %s)\n", expires.Format(time.RFC3339))
	return nil
}

func authLogout(cmd *cobra.Command, args []string) error {
	viper.Set("access_token", "")
	fmt.Println("Logged out")
	return nil
}

// Identity commands
func identityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Identity management commands",
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List identities",
		RunE:  identityList,
	}
	listCmd.Flags().String("type", "", "Filter by type (operator, device, service)")
	listCmd.Flags().String("status", "", "Filter by status (active, suspended, revoked)")
	cmd.AddCommand(listCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "get [id]",
		Short: "Get identity details",
		Args:  cobra.ExactArgs(1),
		RunE:  identityGet,
	})

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new identity",
		RunE:  identityCreate,
	}
	createCmd.Flags().String("type", "operator", "Identity type")
	createCmd.Flags().String("username", "", "Username (for operator)")
	createCmd.Flags().String("email", "", "Email (for operator)")
	createCmd.Flags().StringSlice("groups", []string{}, "Groups")
	cmd.AddCommand(createCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "suspend [id]",
		Short: "Suspend an identity",
		Args:  cobra.ExactArgs(1),
		RunE:  identitySuspend,
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "activate [id]",
		Short: "Activate an identity",
		Args:  cobra.ExactArgs(1),
		RunE:  identityActivate,
	})

	return cmd
}

func identityList(cmd *cobra.Command, args []string) error {
	typeFilter, _ := cmd.Flags().GetString("type")
	statusFilter, _ := cmd.Flags().GetString("status")

	url := apiURL + "/api/v1/identities"
	params := []string{}
	if typeFilter != "" {
		params = append(params, "type="+typeFilter)
	}
	if statusFilter != "" {
		params = append(params, "status="+statusFilter)
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	resp, err := makeRequest("GET", url, nil)
	if err != nil {
		return err
	}

	printJSON(resp)
	return nil
}

func identityGet(cmd *cobra.Command, args []string) error {
	resp, err := makeRequest("GET", apiURL+"/api/v1/identities/"+args[0], nil)
	if err != nil {
		return err
	}
	printJSON(resp)
	return nil
}

func identityCreate(cmd *cobra.Command, args []string) error {
	identityType, _ := cmd.Flags().GetString("type")
	username, _ := cmd.Flags().GetString("username")
	email, _ := cmd.Flags().GetString("email")
	groups, _ := cmd.Flags().GetStringSlice("groups")

	// Generate new key pair for the identity
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	req := map[string]interface{}{
		"type":       identityType,
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"attributes": map[string]interface{}{
			"username": username,
			"email":    email,
			"groups":   groups,
		},
	}

	reqJSON, _ := json.Marshal(req)
	resp, err := makeRequest("POST", apiURL+"/api/v1/identities", reqJSON)
	if err != nil {
		return err
	}

	fmt.Println("Identity created successfully")
	fmt.Printf("Private key (save this securely):\n%s\n", base64.StdEncoding.EncodeToString(priv))
	printJSON(resp)
	return nil
}

func identitySuspend(cmd *cobra.Command, args []string) error {
	req := map[string]string{"reason": "Suspended via CLI"}
	reqJSON, _ := json.Marshal(req)
	_, err := makeRequest("POST", apiURL+"/api/v1/identities/"+args[0]+"/suspend", reqJSON)
	if err != nil {
		return err
	}
	fmt.Println("Identity suspended")
	return nil
}

func identityActivate(cmd *cobra.Command, args []string) error {
	_, err := makeRequest("POST", apiURL+"/api/v1/identities/"+args[0]+"/activate", nil)
	if err != nil {
		return err
	}
	fmt.Println("Identity activated")
	return nil
}

// Device commands
func deviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Device management commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List devices",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("GET", apiURL+"/api/v1/devices", nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "get [id]",
		Short: "Get device details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("GET", apiURL+"/api/v1/devices/"+args[0], nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	execCmd := &cobra.Command{
		Use:   "exec [device-id] [command]",
		Short: "Execute command on device",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := strings.Join(args[1:], " ")
			req := map[string]interface{}{
				"operation_type": "exec",
				"action":         command,
			}
			reqJSON, _ := json.Marshal(req)
			resp, err := makeRequest("POST", apiURL+"/api/v1/devices/"+args[0]+"/operations", reqJSON)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	}
	cmd.AddCommand(execCmd)

	return cmd
}

// Config commands
func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "get [device-id]",
		Short: "Get device configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("GET", apiURL+"/api/v1/devices/"+args[0]+"/config", nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "history [device-id]",
		Short: "Get configuration history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("GET", apiURL+"/api/v1/devices/"+args[0]+"/config/history", nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	return cmd
}

// Policy commands
func policyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy management commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("GET", apiURL+"/api/v1/policies", nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "get [id]",
		Short: "Get policy details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("GET", apiURL+"/api/v1/policies/"+args[0], nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	return cmd
}

// Capability commands
func capabilityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "capability",
		Short: "Capability token commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List capabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Would need subject_id parameter
			fmt.Println("Usage: zt-nms-cli capability list --subject-id <id>")
			return nil
		},
	})

	return cmd
}

// Audit commands
func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit log commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("GET", apiURL+"/api/v1/audit/events", nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Verify audit chain integrity",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := makeRequest("POST", apiURL+"/api/v1/audit/verify", nil)
			if err != nil {
				return err
			}
			printJSON(resp)
			return nil
		},
	})

	return cmd
}

// Keygen command
func keygenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new Ed25519 key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			outputDir, _ := cmd.Flags().GetString("output")
			
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("failed to generate key: %w", err)
			}

			if outputDir != "" {
				// Save to files
				privPath := outputDir + "/private.key"
				pubPath := outputDir + "/public.key"

				if err := os.WriteFile(privPath, priv, 0600); err != nil {
					return fmt.Errorf("failed to write private key: %w", err)
				}
				if err := os.WriteFile(pubPath, pub, 0644); err != nil {
					return fmt.Errorf("failed to write public key: %w", err)
				}

				fmt.Printf("Keys saved to:\n  Private: %s\n  Public: %s\n", privPath, pubPath)
			} else {
				// Print to stdout
				fmt.Printf("Private key:\n%s\n\n", base64.StdEncoding.EncodeToString(priv))
				fmt.Printf("Public key:\n%s\n", base64.StdEncoding.EncodeToString(pub))
			}

			return nil
		},
	}

	cmd.Flags().StringP("output", "o", "", "Output directory for key files")

	return cmd
}

// Helper functions
func makeRequest(method, url string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	
	token := viper.GetString("access_token")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("request failed (%d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func printJSON(data []byte) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		fmt.Println(string(data))
		return
	}
	
	formatted, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Println(string(data))
		return
	}
	fmt.Println(string(formatted))
}
