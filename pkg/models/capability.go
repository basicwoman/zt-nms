package models

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CapabilityStatus represents the status of a capability token
type CapabilityStatus string

const (
	CapabilityStatusActive         CapabilityStatus = "active"
	CapabilityStatusExpired        CapabilityStatus = "expired"
	CapabilityStatusRevoked        CapabilityStatus = "revoked"
	CapabilityStatusPendingApproval CapabilityStatus = "pending_approval"
)

// ActionType represents types of actions on resources
type ActionType string

const (
	ActionConfigRead    ActionType = "config.read"
	ActionConfigWrite   ActionType = "config.write"
	ActionConfigBackup  ActionType = "config.backup"
	ActionConfigDeploy  ActionType = "config.deploy"
	ActionExecCommand   ActionType = "exec.command"
	ActionMonitorRead   ActionType = "monitor.read"
	ActionAdminManage   ActionType = "admin.manage"
)

// ResourceSelector defines which resources a capability grants access to
type ResourceSelector struct {
	Type       string            `json:"type"`                  // device, config, policy
	ID         string            `json:"id,omitempty"`          // specific resource ID
	Pattern    string            `json:"pattern,omitempty"`     // pattern matching (e.g., "router-*")
	Attributes map[string]string `json:"attributes,omitempty"`  // attribute-based selection
}

// ActionConstraints defines constraints on specific actions
type ActionConstraints struct {
	ConfigSections  []string `json:"config_sections,omitempty"`   // allowed config sections
	AllowedCommands []string `json:"allowed_commands,omitempty"`  // allowed CLI commands
	DeniedCommands  []string `json:"denied_commands,omitempty"`   // denied CLI commands
	MaxChanges      int      `json:"max_changes,omitempty"`       // max config changes
	ReadOnly        bool     `json:"read_only,omitempty"`         // read-only access
}

// Grant represents a single permission grant within a capability
type Grant struct {
	Resource         ResourceSelector  `json:"resource"`
	Actions          []ActionType      `json:"actions"`
	Constraints      *ActionConstraints `json:"constraints,omitempty"`
	RequiresApproval bool              `json:"requires_approval,omitempty"`
	ApprovalQuorum   int               `json:"approval_quorum,omitempty"`
	Approvers        []string          `json:"approvers,omitempty"`  // role:xxx or id:xxx
}

// Validity defines the validity period and usage limits of a capability
type Validity struct {
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	MaxUses    int       `json:"max_uses,omitempty"`     // 0 = unlimited
	Renewable  bool      `json:"renewable,omitempty"`
	RenewCount int       `json:"renew_count,omitempty"`  // times renewed
}

// ContextRequirements defines context requirements for capability use
type ContextRequirements struct {
	SourceNetworks  []string `json:"source_networks,omitempty"`   // allowed source CIDRs
	MFARequired     bool     `json:"mfa_required,omitempty"`
	DevicePosture   string   `json:"device_posture,omitempty"`    // compliant, any
	TimeWindows     []string `json:"time_windows,omitempty"`      // HH:MM-HH:MM
	RequireTicket   bool     `json:"require_ticket,omitempty"`    // require change ticket
}

// DelegationRules defines if and how capability can be delegated
type DelegationRules struct {
	Allowed            bool         `json:"allowed"`
	MaxDepth           int          `json:"max_depth,omitempty"`
	DelegatableActions []ActionType `json:"delegatable_actions,omitempty"`
	RequireApproval    bool         `json:"require_approval,omitempty"`
}

// Approval represents an approval signature for a capability
type Approval struct {
	ApproverID   uuid.UUID `json:"approver_id"`
	ApproverRole string    `json:"approver_role"`
	ApprovedAt   time.Time `json:"approved_at"`
	Scope        string    `json:"scope,omitempty"`     // what was approved
	Signature    []byte    `json:"signature"`
}

// CapabilityToken represents a cryptographically signed capability token
type CapabilityToken struct {
	// Header
	Version  uint8     `json:"version"`
	TokenID  uuid.UUID `json:"token_id"`
	Issuer   string    `json:"issuer"`
	IssuedAt time.Time `json:"issued_at"`

	// Subject
	SubjectID     uuid.UUID `json:"subject_id"`
	SubjectHash   []byte    `json:"subject_hash"`   // hash of subject's public key

	// Grants
	Grants []Grant `json:"grants"`

	// Validity
	Validity Validity `json:"validity"`

	// Context Requirements
	ContextRequirements *ContextRequirements `json:"context_requirements,omitempty"`

	// Delegation
	Delegation *DelegationRules `json:"delegation,omitempty"`

	// Parent (if delegated)
	ParentTokenID *uuid.UUID `json:"parent_token_id,omitempty"`
	DelegationDepth int      `json:"delegation_depth,omitempty"`

	// Approvals (populated when required)
	Approvals []Approval `json:"approvals,omitempty"`

	// Signature
	IssuerSignature []byte `json:"issuer_signature"`
}

// CapabilityTokenRequest represents a request for a new capability token
type CapabilityTokenRequest struct {
	SubjectID           uuid.UUID            `json:"subject_id"`
	Grants              []Grant              `json:"grants"`
	ValidityDuration    time.Duration        `json:"validity_duration"`
	ContextRequirements *ContextRequirements `json:"context_requirements,omitempty"`
	Delegation          *DelegationRules     `json:"delegation,omitempty"`
	Justification       string               `json:"justification"`
	TicketID            string               `json:"ticket_id,omitempty"`
}

// Hash computes the hash of the capability token (excluding signature)
func (ct *CapabilityToken) Hash() []byte {
	h := sha256.New()
	
	// Version
	binary.Write(h, binary.BigEndian, ct.Version)
	
	// Token ID
	h.Write(ct.TokenID[:])
	
	// Issuer
	h.Write([]byte(ct.Issuer))
	
	// Issued At
	binary.Write(h, binary.BigEndian, ct.IssuedAt.Unix())
	
	// Subject
	h.Write(ct.SubjectID[:])
	h.Write(ct.SubjectHash)
	
	// Grants (serialized as JSON for simplicity)
	grantsJSON, _ := json.Marshal(ct.Grants)
	h.Write(grantsJSON)
	
	// Validity
	binary.Write(h, binary.BigEndian, ct.Validity.NotBefore.Unix())
	binary.Write(h, binary.BigEndian, ct.Validity.NotAfter.Unix())
	binary.Write(h, binary.BigEndian, int64(ct.Validity.MaxUses))
	
	// Context Requirements
	if ct.ContextRequirements != nil {
		ctxJSON, _ := json.Marshal(ct.ContextRequirements)
		h.Write(ctxJSON)
	}
	
	// Delegation
	if ct.Delegation != nil {
		delJSON, _ := json.Marshal(ct.Delegation)
		h.Write(delJSON)
	}
	
	// Parent
	if ct.ParentTokenID != nil {
		h.Write(ct.ParentTokenID[:])
	}
	
	return h.Sum(nil)
}

// TokenHash returns the hash of the token for revocation lookups
func (ct *CapabilityToken) TokenHash() []byte {
	h := sha256.Sum256(ct.TokenID[:])
	return h[:]
}

// IsValid checks if the capability token is currently valid
func (ct *CapabilityToken) IsValid(currentTime time.Time) bool {
	if currentTime.Before(ct.Validity.NotBefore) {
		return false
	}
	if currentTime.After(ct.Validity.NotAfter) {
		return false
	}
	return true
}

// Verify verifies the token's signature
func (ct *CapabilityToken) Verify(issuerPublicKey ed25519.PublicKey) bool {
	hash := ct.Hash()
	return ed25519.Verify(issuerPublicKey, hash, ct.IssuerSignature)
}

// Sign signs the capability token
func (ct *CapabilityToken) Sign(issuerPrivateKey ed25519.PrivateKey) {
	hash := ct.Hash()
	ct.IssuerSignature = ed25519.Sign(issuerPrivateKey, hash)
}

// Allows checks if the capability allows a specific action on a resource
func (ct *CapabilityToken) Allows(action ActionType, resourceType, resourceID string) bool {
	for _, grant := range ct.Grants {
		if !ct.matchesResource(grant.Resource, resourceType, resourceID) {
			continue
		}
		for _, allowedAction := range grant.Actions {
			if allowedAction == action {
				return true
			}
		}
	}
	return false
}

// matchesResource checks if a resource selector matches the given resource
func (ct *CapabilityToken) matchesResource(selector ResourceSelector, resourceType, resourceID string) bool {
	if selector.Type != resourceType {
		return false
	}
	
	if selector.ID != "" && selector.ID != resourceID {
		return false
	}
	
	if selector.Pattern != "" {
		// Simple pattern matching (could be enhanced)
		// For now, just prefix matching with *
		if len(selector.Pattern) > 0 && selector.Pattern[len(selector.Pattern)-1] == '*' {
			prefix := selector.Pattern[:len(selector.Pattern)-1]
			if len(resourceID) < len(prefix) || resourceID[:len(prefix)] != prefix {
				return false
			}
		}
	}
	
	return true
}

// GetGrantForResource returns the grant that matches the resource, if any
func (ct *CapabilityToken) GetGrantForResource(resourceType, resourceID string) *Grant {
	for i := range ct.Grants {
		if ct.matchesResource(ct.Grants[i].Resource, resourceType, resourceID) {
			return &ct.Grants[i]
		}
	}
	return nil
}

// RequiresApprovalFor checks if the action requires approval
func (ct *CapabilityToken) RequiresApprovalFor(action ActionType, resourceType, resourceID string) bool {
	grant := ct.GetGrantForResource(resourceType, resourceID)
	if grant == nil {
		return false
	}
	return grant.RequiresApproval
}

// HasSufficientApprovals checks if the capability has enough approvals
func (ct *CapabilityToken) HasSufficientApprovals(resourceType, resourceID string) bool {
	grant := ct.GetGrantForResource(resourceType, resourceID)
	if grant == nil || !grant.RequiresApproval {
		return true
	}
	return len(ct.Approvals) >= grant.ApprovalQuorum
}

// NewCapabilityToken creates a new capability token
func NewCapabilityToken(
	issuer string,
	subjectID uuid.UUID,
	subjectPublicKey ed25519.PublicKey,
	grants []Grant,
	validity Validity,
	contextReqs *ContextRequirements,
	delegation *DelegationRules,
) *CapabilityToken {
	subjectHash := sha256.Sum256(subjectPublicKey)
	
	return &CapabilityToken{
		Version:             1,
		TokenID:             uuid.New(),
		Issuer:              issuer,
		IssuedAt:            time.Now().UTC(),
		SubjectID:           subjectID,
		SubjectHash:         subjectHash[:],
		Grants:              grants,
		Validity:            validity,
		ContextRequirements: contextReqs,
		Delegation:          delegation,
	}
}
