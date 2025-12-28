package models

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ConfigFormat represents the format of configuration
type ConfigFormat string

const (
	ConfigFormatNormalized ConfigFormat = "normalized"
	ConfigFormatVendor     ConfigFormat = "vendor"
	ConfigFormatRaw        ConfigFormat = "raw"
)

// DeploymentStatus represents the deployment status of a config block
type DeploymentStatus string

const (
	DeploymentStatusPending   DeploymentStatus = "pending"
	DeploymentStatusApproved  DeploymentStatus = "approved"
	DeploymentStatusDeploying DeploymentStatus = "deploying"
	DeploymentStatusApplied   DeploymentStatus = "applied"
	DeploymentStatusFailed    DeploymentStatus = "failed"
	DeploymentStatusRolledBack DeploymentStatus = "rolled_back"
)

// ConfigIntent represents the high-level intent of a configuration change
type ConfigIntent struct {
	Description string   `json:"description"`
	PolicyRefs  []string `json:"policy_refs,omitempty"`
	ChangeTicket string  `json:"change_ticket,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// ConfigTree represents a hierarchical configuration structure
type ConfigTree struct {
	Interfaces map[string]InterfaceConfig `json:"interfaces,omitempty"`
	Routing    *RoutingConfig             `json:"routing,omitempty"`
	Security   *SecurityConfig            `json:"security,omitempty"`
	Services   *ServicesConfig            `json:"services,omitempty"`
	System     *SystemConfig              `json:"system,omitempty"`
	Custom     map[string]interface{}     `json:"custom,omitempty"`
}

// InterfaceConfig represents interface configuration
type InterfaceConfig struct {
	Enabled     bool              `json:"enabled"`
	IPAddress   string            `json:"ip_address,omitempty"`
	IPv6Address string            `json:"ipv6_address,omitempty"`
	Description string            `json:"description,omitempty"`
	MTU         int               `json:"mtu,omitempty"`
	Speed       string            `json:"speed,omitempty"`
	Duplex      string            `json:"duplex,omitempty"`
	VRF         string            `json:"vrf,omitempty"`
	ACLIn       string            `json:"acl_in,omitempty"`
	ACLOut      string            `json:"acl_out,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// RoutingConfig represents routing configuration
type RoutingConfig struct {
	BGP    *BGPConfig              `json:"bgp,omitempty"`
	OSPF   *OSPFConfig             `json:"ospf,omitempty"`
	Static []StaticRoute           `json:"static,omitempty"`
	VRFs   map[string]VRFConfig    `json:"vrfs,omitempty"`
}

// BGPConfig represents BGP configuration
type BGPConfig struct {
	LocalAS   uint32                 `json:"local_as"`
	RouterID  string                 `json:"router_id,omitempty"`
	Neighbors map[string]BGPNeighbor `json:"neighbors,omitempty"`
	Networks  []string               `json:"networks,omitempty"`
}

// BGPNeighbor represents a BGP neighbor configuration
type BGPNeighbor struct {
	RemoteAS     uint32 `json:"remote_as"`
	Description  string `json:"description,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	UpdateSource string `json:"update_source,omitempty"`
	EBGPMultihop int    `json:"ebgp_multihop,omitempty"`
	RouteMapIn   string `json:"route_map_in,omitempty"`
	RouteMapOut  string `json:"route_map_out,omitempty"`
}

// OSPFConfig represents OSPF configuration
type OSPFConfig struct {
	ProcessID  int                `json:"process_id"`
	RouterID   string             `json:"router_id,omitempty"`
	Areas      map[string]OSPFArea `json:"areas,omitempty"`
	Networks   []OSPFNetwork      `json:"networks,omitempty"`
}

// OSPFArea represents an OSPF area
type OSPFArea struct {
	Type           string `json:"type,omitempty"` // normal, stub, nssa
	Authentication string `json:"authentication,omitempty"`
}

// OSPFNetwork represents an OSPF network statement
type OSPFNetwork struct {
	Network string `json:"network"`
	Area    string `json:"area"`
}

// StaticRoute represents a static route
type StaticRoute struct {
	Prefix    string `json:"prefix"`
	NextHop   string `json:"next_hop,omitempty"`
	Interface string `json:"interface,omitempty"`
	Distance  int    `json:"distance,omitempty"`
	Tag       int    `json:"tag,omitempty"`
}

// VRFConfig represents VRF configuration
type VRFConfig struct {
	RD          string   `json:"rd,omitempty"`
	ImportRT    []string `json:"import_rt,omitempty"`
	ExportRT    []string `json:"export_rt,omitempty"`
	Description string   `json:"description,omitempty"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	ACLs       map[string]ACL       `json:"acls,omitempty"`
	PrefixLists map[string]PrefixList `json:"prefix_lists,omitempty"`
	RouteMaps  map[string]RouteMap  `json:"route_maps,omitempty"`
	Firewall   *FirewallConfig      `json:"firewall,omitempty"`
}

// ACL represents an access control list
type ACL struct {
	Type    string    `json:"type"` // standard, extended, ipv6
	Entries []ACLEntry `json:"entries"`
}

// ACLEntry represents an ACL entry
type ACLEntry struct {
	Sequence    int    `json:"sequence"`
	Action      string `json:"action"` // permit, deny
	Protocol    string `json:"protocol,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination,omitempty"`
	Port        string `json:"port,omitempty"`
	Log         bool   `json:"log,omitempty"`
}

// PrefixList represents a prefix list
type PrefixList struct {
	Entries []PrefixListEntry `json:"entries"`
}

// PrefixListEntry represents a prefix list entry
type PrefixListEntry struct {
	Sequence int    `json:"sequence"`
	Action   string `json:"action"` // permit, deny
	Prefix   string `json:"prefix"`
	GE       int    `json:"ge,omitempty"`
	LE       int    `json:"le,omitempty"`
}

// RouteMap represents a route map
type RouteMap struct {
	Entries []RouteMapEntry `json:"entries"`
}

// RouteMapEntry represents a route map entry
type RouteMapEntry struct {
	Sequence int                    `json:"sequence"`
	Action   string                 `json:"action"` // permit, deny
	Match    map[string]string      `json:"match,omitempty"`
	Set      map[string]interface{} `json:"set,omitempty"`
}

// FirewallConfig represents firewall configuration
type FirewallConfig struct {
	Zones   map[string]FirewallZone `json:"zones,omitempty"`
	Rules   []FirewallRule          `json:"rules,omitempty"`
	NAT     []NATRule               `json:"nat,omitempty"`
}

// FirewallZone represents a firewall zone
type FirewallZone struct {
	Interfaces []string `json:"interfaces"`
	Description string  `json:"description,omitempty"`
}

// FirewallRule represents a firewall rule
type FirewallRule struct {
	Name        string   `json:"name"`
	Action      string   `json:"action"` // allow, deny, reject
	FromZone    string   `json:"from_zone"`
	ToZone      string   `json:"to_zone"`
	Source      string   `json:"source,omitempty"`
	Destination string   `json:"destination,omitempty"`
	Services    []string `json:"services,omitempty"`
	Log         bool     `json:"log,omitempty"`
	Enabled     bool     `json:"enabled"`
}

// NATRule represents a NAT rule
type NATRule struct {
	Type        string `json:"type"` // source, destination, static
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Translated  string `json:"translated"`
	Interface   string `json:"interface,omitempty"`
}

// ServicesConfig represents services configuration
type ServicesConfig struct {
	SSH    *SSHConfig    `json:"ssh,omitempty"`
	SNMP   *SNMPConfig   `json:"snmp,omitempty"`
	NTP    *NTPConfig    `json:"ntp,omitempty"`
	Syslog *SyslogConfig `json:"syslog,omitempty"`
}

// SSHConfig represents SSH configuration
type SSHConfig struct {
	Enabled    bool   `json:"enabled"`
	Port       int    `json:"port,omitempty"`
	Version    int    `json:"version,omitempty"`
	Timeout    int    `json:"timeout,omitempty"`
	MaxRetries int    `json:"max_retries,omitempty"`
}

// SNMPConfig represents SNMP configuration
type SNMPConfig struct {
	Enabled     bool              `json:"enabled"`
	Version     string            `json:"version"` // v2c, v3
	Location    string            `json:"location,omitempty"`
	Contact     string            `json:"contact,omitempty"`
	Communities []SNMPCommunity   `json:"communities,omitempty"`
	Users       []SNMPUser        `json:"users,omitempty"`
}

// SNMPCommunity represents an SNMP community (v2c)
type SNMPCommunity struct {
	Name       string `json:"name"`
	Permission string `json:"permission"` // ro, rw
	ACL        string `json:"acl,omitempty"`
}

// SNMPUser represents an SNMP user (v3)
type SNMPUser struct {
	Name          string `json:"name"`
	AuthProtocol  string `json:"auth_protocol,omitempty"`
	AuthPassword  string `json:"auth_password,omitempty"`
	PrivProtocol  string `json:"priv_protocol,omitempty"`
	PrivPassword  string `json:"priv_password,omitempty"`
	Group         string `json:"group,omitempty"`
}

// NTPConfig represents NTP configuration
type NTPConfig struct {
	Enabled bool        `json:"enabled"`
	Servers []NTPServer `json:"servers,omitempty"`
}

// NTPServer represents an NTP server
type NTPServer struct {
	Address string `json:"address"`
	Prefer  bool   `json:"prefer,omitempty"`
	Key     int    `json:"key,omitempty"`
}

// SyslogConfig represents syslog configuration
type SyslogConfig struct {
	Enabled bool           `json:"enabled"`
	Servers []SyslogServer `json:"servers,omitempty"`
}

// SyslogServer represents a syslog server
type SyslogServer struct {
	Address  string `json:"address"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // udp, tcp, tls
	Facility string `json:"facility,omitempty"`
	Level    string `json:"level,omitempty"`
}

// SystemConfig represents system configuration
type SystemConfig struct {
	Hostname   string            `json:"hostname,omitempty"`
	Domain     string            `json:"domain,omitempty"`
	DNS        []string          `json:"dns,omitempty"`
	Banner     *BannerConfig     `json:"banner,omitempty"`
	Users      []LocalUser       `json:"users,omitempty"`
	AAA        *AAAConfig        `json:"aaa,omitempty"`
}

// BannerConfig represents banner configuration
type BannerConfig struct {
	Login string `json:"login,omitempty"`
	MOTD  string `json:"motd,omitempty"`
	Exec  string `json:"exec,omitempty"`
}

// LocalUser represents a local user account
type LocalUser struct {
	Username  string `json:"username"`
	Privilege int    `json:"privilege,omitempty"`
	Secret    string `json:"secret,omitempty"`
	SSHKey    string `json:"ssh_key,omitempty"`
}

// AAAConfig represents AAA configuration
type AAAConfig struct {
	Authentication []AAAMethod `json:"authentication,omitempty"`
	Authorization  []AAAMethod `json:"authorization,omitempty"`
	Accounting     []AAAMethod `json:"accounting,omitempty"`
}

// AAAMethod represents an AAA method
type AAAMethod struct {
	Type    string   `json:"type"` // login, exec, commands
	Methods []string `json:"methods"`
}

// VendorConfig represents vendor-specific configuration
type VendorConfig struct {
	Format   string   `json:"format"` // ios, ios-xe, junos, etc.
	Commands []string `json:"commands"`
}

// ConfigDiff represents differences between configurations
type ConfigDiff struct {
	Added    []ConfigChange `json:"added,omitempty"`
	Modified []ConfigChange `json:"modified,omitempty"`
	Removed  []ConfigChange `json:"removed,omitempty"`
}

// ConfigChange represents a single configuration change
type ConfigChange struct {
	Path     string      `json:"path"`
	OldValue interface{} `json:"old_value,omitempty"`
	NewValue interface{} `json:"new_value,omitempty"`
}

// ValidationResult represents the result of configuration validation
type ValidationResult struct {
	SyntaxCheck     string                    `json:"syntax_check"`
	PolicyCheck     string                    `json:"policy_check"`
	SecurityCheck   string                    `json:"security_check"`
	SimulationResult *SimulationResult        `json:"simulation_result,omitempty"`
	Errors          []ConfigValidationError   `json:"errors,omitempty"`
	Warnings        []ConfigValidationWarning `json:"warnings,omitempty"`
}

// SimulationResult represents results of configuration simulation
type SimulationResult struct {
	Reachability string `json:"reachability"`
	NoLoops      string `json:"no_loops"`
	Consistency  string `json:"consistency"`
}

// ConfigValidationError represents a configuration validation error
type ConfigValidationError struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ConfigValidationWarning represents a configuration validation warning
type ConfigValidationWarning struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ConfigSignature represents a signature on a configuration
type ConfigSignature struct {
	Identity  uuid.UUID `json:"identity"`
	Role      string    `json:"role,omitempty"`
	Signature []byte    `json:"signature"`
	Timestamp time.Time `json:"timestamp"`
}

// ConfigBlock represents an immutable configuration block in the chain
type ConfigBlock struct {
	// Header
	ID         uuid.UUID `json:"id" db:"id"`
	DeviceID   uuid.UUID `json:"device_id" db:"device_id"`
	Sequence   int64     `json:"sequence" db:"sequence"`
	PrevHash   []byte    `json:"prev_hash" db:"prev_hash"`
	MerkleRoot []byte    `json:"merkle_root" db:"merkle_root"`
	BlockHash  []byte    `json:"block_hash" db:"block_hash"`
	Timestamp  time.Time `json:"timestamp" db:"timestamp"`

	// Intent
	Intent *ConfigIntent `json:"intent,omitempty" db:"intent"`

	// Configuration
	Configuration *ConfigurationPayload `json:"configuration" db:"configuration"`

	// Diff from previous
	Diff *ConfigDiff `json:"diff,omitempty" db:"diff"`

	// Validation
	Validation *ValidationResult `json:"validation,omitempty" db:"validation"`

	// Signatures
	AuthorID         uuid.UUID        `json:"author_id" db:"author_id"`
	AuthorSignature  []byte           `json:"author_signature" db:"author_signature"`
	Approvals        []ConfigSignature `json:"approvals,omitempty" db:"approvals"`
	SystemSignature  []byte           `json:"system_signature" db:"system_signature"`

	// Deployment
	DeploymentStatus DeploymentStatus `json:"deployment_status" db:"deployment_status"`
	DeviceSignature  []byte           `json:"device_signature,omitempty" db:"device_signature"`
	AppliedAt        *time.Time       `json:"applied_at,omitempty" db:"applied_at"`
	DeviceConfigHash []byte           `json:"device_config_hash,omitempty" db:"device_config_hash"`
}

// ConfigurationPayload contains the actual configuration data
type ConfigurationPayload struct {
	Format        ConfigFormat   `json:"format"`
	Tree          *ConfigTree    `json:"tree,omitempty"`
	VendorConfig  *VendorConfig  `json:"vendor_config,omitempty"`
	Raw           string         `json:"raw,omitempty"`
}

// ComputeHash computes the hash of the configuration block
func (cb *ConfigBlock) ComputeHash() []byte {
	h := sha256.New()

	// Header fields
	h.Write(cb.ID[:])
	h.Write(cb.DeviceID[:])
	binary.Write(h, binary.BigEndian, cb.Sequence)
	if cb.PrevHash != nil {
		h.Write(cb.PrevHash)
	}
	h.Write(cb.MerkleRoot)
	binary.Write(h, binary.BigEndian, cb.Timestamp.Unix())

	// Intent
	if cb.Intent != nil {
		intentJSON, _ := json.Marshal(cb.Intent)
		h.Write(intentJSON)
	}

	// Configuration
	if cb.Configuration != nil {
		configJSON, _ := json.Marshal(cb.Configuration)
		h.Write(configJSON)
	}

	// Diff
	if cb.Diff != nil {
		diffJSON, _ := json.Marshal(cb.Diff)
		h.Write(diffJSON)
	}

	// Validation
	if cb.Validation != nil {
		validJSON, _ := json.Marshal(cb.Validation)
		h.Write(validJSON)
	}

	// Author
	h.Write(cb.AuthorID[:])

	return h.Sum(nil)
}

// Sign signs the configuration block with the author's private key
func (cb *ConfigBlock) Sign(privateKey ed25519.PrivateKey) {
	cb.BlockHash = cb.ComputeHash()
	cb.AuthorSignature = ed25519.Sign(privateKey, cb.BlockHash)
}

// Verify verifies the author's signature
func (cb *ConfigBlock) Verify(publicKey ed25519.PublicKey) bool {
	expectedHash := cb.ComputeHash()
	return ed25519.Verify(publicKey, expectedHash, cb.AuthorSignature)
}

// VerifyChain verifies this block links to the previous block
func (cb *ConfigBlock) VerifyChain(prevBlock *ConfigBlock) bool {
	if prevBlock == nil {
		return cb.PrevHash == nil && cb.Sequence == 1
	}
	if cb.Sequence != prevBlock.Sequence+1 {
		return false
	}
	if len(cb.PrevHash) != len(prevBlock.BlockHash) {
		return false
	}
	for i := range cb.PrevHash {
		if cb.PrevHash[i] != prevBlock.BlockHash[i] {
			return false
		}
	}
	return true
}

// NewConfigBlock creates a new configuration block
func NewConfigBlock(
	deviceID uuid.UUID,
	sequence int64,
	prevHash []byte,
	intent *ConfigIntent,
	config *ConfigurationPayload,
	diff *ConfigDiff,
	validation *ValidationResult,
	authorID uuid.UUID,
) *ConfigBlock {
	cb := &ConfigBlock{
		ID:               uuid.New(),
		DeviceID:         deviceID,
		Sequence:         sequence,
		PrevHash:         prevHash,
		Timestamp:        time.Now().UTC(),
		Intent:           intent,
		Configuration:    config,
		Diff:             diff,
		Validation:       validation,
		AuthorID:         authorID,
		DeploymentStatus: DeploymentStatusPending,
	}

	// Compute Merkle root of configuration
	if config != nil && config.Tree != nil {
		cb.MerkleRoot = computeConfigMerkleRoot(config.Tree)
	}

	return cb
}

// computeConfigMerkleRoot computes the Merkle root of a configuration tree
func computeConfigMerkleRoot(tree *ConfigTree) []byte {
	var hashes [][]byte

	// Hash each section
	if tree.Interfaces != nil {
		data, _ := json.Marshal(tree.Interfaces)
		h := sha256.Sum256(data)
		hashes = append(hashes, h[:])
	}
	if tree.Routing != nil {
		data, _ := json.Marshal(tree.Routing)
		h := sha256.Sum256(data)
		hashes = append(hashes, h[:])
	}
	if tree.Security != nil {
		data, _ := json.Marshal(tree.Security)
		h := sha256.Sum256(data)
		hashes = append(hashes, h[:])
	}
	if tree.Services != nil {
		data, _ := json.Marshal(tree.Services)
		h := sha256.Sum256(data)
		hashes = append(hashes, h[:])
	}
	if tree.System != nil {
		data, _ := json.Marshal(tree.System)
		h := sha256.Sum256(data)
		hashes = append(hashes, h[:])
	}
	if tree.Custom != nil {
		data, _ := json.Marshal(tree.Custom)
		h := sha256.Sum256(data)
		hashes = append(hashes, h[:])
	}

	if len(hashes) == 0 {
		return nil
	}

	// Build Merkle tree
	for len(hashes) > 1 {
		var newHashes [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := append(hashes[i], hashes[i+1]...)
				h := sha256.Sum256(combined)
				newHashes = append(newHashes, h[:])
			} else {
				newHashes = append(newHashes, hashes[i])
			}
		}
		hashes = newHashes
	}

	return hashes[0]
}
