package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PolicyType represents the type of policy
type PolicyType string

const (
	PolicyTypeAccess     PolicyType = "access"
	PolicyTypeConfig     PolicyType = "config"
	PolicyTypeDeployment PolicyType = "deployment"
	PolicyTypeNetwork    PolicyType = "network"
)

// PolicyStatus represents the status of a policy
type PolicyStatus string

const (
	PolicyStatusDraft    PolicyStatus = "draft"
	PolicyStatusActive   PolicyStatus = "active"
	PolicyStatusArchived PolicyStatus = "archived"
)

// PolicyEffect represents the effect of a policy rule
type PolicyEffect string

const (
	PolicyEffectAllow  PolicyEffect = "allow"
	PolicyEffectDeny   PolicyEffect = "deny"
	PolicyEffectStepUp PolicyEffect = "step_up" // require additional authentication
)

// Policy represents a complete policy definition
type Policy struct {
	ID             uuid.UUID    `json:"id" db:"id"`
	Name           string       `json:"name" db:"name"`
	Version        int          `json:"version" db:"version"`
	Description    string       `json:"description" db:"description"`
	Type           PolicyType   `json:"type" db:"type"`
	Definition     PolicyDefinition `json:"definition" db:"definition"`
	CompiledPolicy []byte       `json:"compiled,omitempty" db:"compiled"`
	Status         PolicyStatus `json:"status" db:"status"`
	EffectiveFrom  *time.Time   `json:"effective_from,omitempty" db:"effective_from"`
	EffectiveUntil *time.Time   `json:"effective_until,omitempty" db:"effective_until"`
	CreatedAt      time.Time    `json:"created_at" db:"created_at"`
	CreatedBy      uuid.UUID    `json:"created_by" db:"created_by"`
	ApprovedBy     *uuid.UUID   `json:"approved_by,omitempty" db:"approved_by"`
	ApprovalSig    []byte       `json:"approval_signature,omitempty" db:"approval_signature"`
}

// PolicyDefinition contains the policy rules
type PolicyDefinition struct {
	Rules       []PolicyRule      `json:"rules"`
	Defaults    *PolicyDefaults   `json:"defaults,omitempty"`
	Variables   map[string]interface{} `json:"variables,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PolicyDefaults defines default behavior
type PolicyDefaults struct {
	Effect      PolicyEffect `json:"effect"`
	Obligations []Obligation `json:"obligations,omitempty"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Priority    int              `json:"priority,omitempty"`
	Subjects    SubjectMatcher   `json:"subjects"`
	Resources   ResourceMatcher  `json:"resources"`
	Actions     []string         `json:"actions"`
	Conditions  []Condition      `json:"conditions,omitempty"`
	Effect      PolicyEffect     `json:"effect"`
	Obligations []Obligation     `json:"obligations,omitempty"`
}

// SubjectMatcher defines conditions for matching subjects
type SubjectMatcher struct {
	Identities []IdentityMatcher     `json:"identities,omitempty"`
	Groups     []string              `json:"groups,omitempty"`
	Roles      []string              `json:"roles,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Any        bool                  `json:"any,omitempty"` // match any subject
}

// IdentityMatcher defines conditions for matching a specific identity
type IdentityMatcher struct {
	Type       IdentityType `json:"type,omitempty"`
	ID         string       `json:"id,omitempty"`
	Pattern    string       `json:"pattern,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// ResourceMatcher defines conditions for matching resources
type ResourceMatcher struct {
	Types      []string              `json:"types,omitempty"`
	IDs        []string              `json:"ids,omitempty"`
	Patterns   []string              `json:"patterns,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Tags       []string              `json:"tags,omitempty"`
	Any        bool                  `json:"any,omitempty"` // match any resource
}

// Condition represents a condition for rule evaluation
type Condition struct {
	Type     ConditionType          `json:"type"`
	Field    string                 `json:"field"`
	Operator ConditionOperator      `json:"operator"`
	Value    interface{}            `json:"value"`
	Negate   bool                   `json:"negate,omitempty"`
}

// ConditionType represents the type of condition
type ConditionType string

const (
	ConditionTypeContext   ConditionType = "context"
	ConditionTypeTime      ConditionType = "time"
	ConditionTypeSubject   ConditionType = "subject"
	ConditionTypeResource  ConditionType = "resource"
	ConditionTypeExternal  ConditionType = "external" // external data source
)

// ConditionOperator represents comparison operators
type ConditionOperator string

const (
	ConditionOpEquals      ConditionOperator = "eq"
	ConditionOpNotEquals   ConditionOperator = "ne"
	ConditionOpGreater     ConditionOperator = "gt"
	ConditionOpGreaterEq   ConditionOperator = "gte"
	ConditionOpLess        ConditionOperator = "lt"
	ConditionOpLessEq      ConditionOperator = "lte"
	ConditionOpIn          ConditionOperator = "in"
	ConditionOpNotIn       ConditionOperator = "not_in"
	ConditionOpContains    ConditionOperator = "contains"
	ConditionOpStartsWith  ConditionOperator = "starts_with"
	ConditionOpEndsWith    ConditionOperator = "ends_with"
	ConditionOpMatches     ConditionOperator = "matches" // regex
	ConditionOpExists      ConditionOperator = "exists"
	ConditionOpBetween     ConditionOperator = "between"
)

// Obligation represents an obligation to be fulfilled
type Obligation struct {
	Type       ObligationType `json:"type"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// ObligationType represents types of obligations
type ObligationType string

const (
	ObligationTypeLog              ObligationType = "log"
	ObligationTypeNotify           ObligationType = "notify"
	ObligationTypeRequireApproval  ObligationType = "require_approval"
	ObligationTypeRecordSession    ObligationType = "record_session"
	ObligationTypeTimeLimit        ObligationType = "time_limit"
	ObligationTypeRequireJustification ObligationType = "require_justification"
	ObligationTypeAlert            ObligationType = "alert"
	ObligationTypeAudit            ObligationType = "audit"
)

// PolicyEvaluationRequest represents a request to evaluate a policy
type PolicyEvaluationRequest struct {
	Subject  PolicySubject  `json:"subject"`
	Resource PolicyResource `json:"resource"`
	Action   string         `json:"action"`
	Context  PolicyContext  `json:"context"`
}

// PolicySubject represents the subject of a policy evaluation
type PolicySubject struct {
	ID         uuid.UUID              `json:"id"`
	Type       IdentityType           `json:"type"`
	Groups     []string               `json:"groups,omitempty"`
	Roles      []string               `json:"roles,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// PolicyResource represents the resource of a policy evaluation
type PolicyResource struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
}

// PolicyContext represents the context of a policy evaluation
type PolicyContext struct {
	Time           time.Time              `json:"time"`
	SourceIP       string                 `json:"source_ip,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	MFAVerified    bool                   `json:"mfa_verified,omitempty"`
	DevicePosture  string                 `json:"device_posture,omitempty"`
	ChangeTicket   *ChangeTicket          `json:"change_ticket,omitempty"`
	Emergency      *EmergencyContext      `json:"emergency,omitempty"`
	Custom         map[string]interface{} `json:"custom,omitempty"`
}

// ChangeTicket represents a change ticket reference
type ChangeTicket struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Approved bool   `json:"approved"`
}

// EmergencyContext represents emergency access context
type EmergencyContext struct {
	Declared    bool   `json:"declared"`
	EmergencyID string `json:"emergency_id"`
	Reason      string `json:"reason"`
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Decision     PolicyEffect     `json:"decision"`
	MatchedRules []MatchedRule    `json:"matched_rules,omitempty"`
	Obligations  []Obligation     `json:"obligations,omitempty"`
	Constraints  map[string]interface{} `json:"constraints,omitempty"`
	Reason       string           `json:"reason,omitempty"`
	EvaluatedAt  time.Time        `json:"evaluated_at"`
	CacheKey     string           `json:"cache_key,omitempty"`
	CacheTTL     int              `json:"cache_ttl,omitempty"`
}

// MatchedRule represents a rule that matched during evaluation
type MatchedRule struct {
	PolicyID   uuid.UUID    `json:"policy_id"`
	PolicyName string       `json:"policy_name"`
	RuleName   string       `json:"rule_name"`
	Effect     PolicyEffect `json:"effect"`
	Priority   int          `json:"priority"`
}

// NetworkPolicy represents a network-level policy
type NetworkPolicy struct {
	ID          uuid.UUID           `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Rules       []NetworkPolicyRule `json:"rules"`
	DefaultAction string            `json:"default_action"` // allow, deny
}

// NetworkPolicyRule represents a network policy rule
type NetworkPolicyRule struct {
	Name        string              `json:"name"`
	Source      NetworkEndpoint     `json:"source"`
	Destination NetworkEndpoint     `json:"destination"`
	Action      string              `json:"action"` // allow, deny
	Protocols   []ProtocolMatch     `json:"protocols,omitempty"`
	Constraints NetworkConstraints  `json:"constraints,omitempty"`
	Log         bool                `json:"log,omitempty"`
}

// NetworkEndpoint represents a network endpoint
type NetworkEndpoint struct {
	Type     string   `json:"type"` // network, host, any
	Networks []string `json:"networks,omitempty"`
	Hosts    []string `json:"hosts,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// ProtocolMatch represents protocol matching criteria
type ProtocolMatch struct {
	Protocol  string `json:"protocol"` // tcp, udp, icmp, any
	PortStart int    `json:"port_start,omitempty"`
	PortEnd   int    `json:"port_end,omitempty"`
}

// NetworkConstraints represents constraints on network traffic
type NetworkConstraints struct {
	EncryptionRequired   bool     `json:"encryption_required,omitempty"`
	MinTLSVersion        string   `json:"min_tls_version,omitempty"`
	AuthenticationMethod []string `json:"authentication_method,omitempty"`
	MaxBandwidth         string   `json:"max_bandwidth,omitempty"`
	QoSClass             string   `json:"qos_class,omitempty"`
}

// PolicyVersion represents a historical version of a policy
type PolicyVersion struct {
	ID         uuid.UUID        `json:"id" db:"id"`
	PolicyID   uuid.UUID        `json:"policy_id" db:"policy_id"`
	Version    int              `json:"version" db:"version"`
	Definition PolicyDefinition `json:"definition" db:"definition"`
	CreatedAt  time.Time        `json:"created_at" db:"created_at"`
	CreatedBy  uuid.UUID        `json:"created_by" db:"created_by"`
	ChangeLog  string           `json:"change_log,omitempty" db:"change_log"`
}

// NewPolicy creates a new policy
func NewPolicy(name string, policyType PolicyType, description string, definition PolicyDefinition, createdBy uuid.UUID) *Policy {
	return &Policy{
		ID:          uuid.New(),
		Name:        name,
		Version:     1,
		Description: description,
		Type:        policyType,
		Definition:  definition,
		Status:      PolicyStatusDraft,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   createdBy,
	}
}

// Evaluate evaluates the policy against a request (basic implementation)
func (p *Policy) Evaluate(req PolicyEvaluationRequest) *PolicyDecision {
	decision := &PolicyDecision{
		Decision:    PolicyEffectDeny, // default deny
		EvaluatedAt: time.Now().UTC(),
	}

	for _, rule := range p.Definition.Rules {
		if p.matchesRule(rule, req) {
			decision.MatchedRules = append(decision.MatchedRules, MatchedRule{
				PolicyID:   p.ID,
				PolicyName: p.Name,
				RuleName:   rule.Name,
				Effect:     rule.Effect,
				Priority:   rule.Priority,
			})
			
			if rule.Effect == PolicyEffectAllow {
				decision.Decision = PolicyEffectAllow
				decision.Obligations = append(decision.Obligations, rule.Obligations...)
			} else if rule.Effect == PolicyEffectDeny {
				decision.Decision = PolicyEffectDeny
				decision.Reason = "Denied by rule: " + rule.Name
				return decision
			} else if rule.Effect == PolicyEffectStepUp {
				decision.Decision = PolicyEffectStepUp
				decision.Obligations = append(decision.Obligations, rule.Obligations...)
			}
		}
	}

	return decision
}

// matchesRule checks if a rule matches the request
func (p *Policy) matchesRule(rule PolicyRule, req PolicyEvaluationRequest) bool {
	// Check subjects
	if !p.matchesSubject(rule.Subjects, req.Subject) {
		return false
	}

	// Check resources
	if !p.matchesResource(rule.Resources, req.Resource) {
		return false
	}

	// Check actions
	actionMatched := false
	for _, action := range rule.Actions {
		if action == req.Action || action == "*" {
			actionMatched = true
			break
		}
	}
	if !actionMatched {
		return false
	}

	// Check conditions
	for _, condition := range rule.Conditions {
		if !p.evaluateCondition(condition, req) {
			return false
		}
	}

	return true
}

// matchesSubject checks if the subject matches
func (p *Policy) matchesSubject(matcher SubjectMatcher, subject PolicySubject) bool {
	if matcher.Any {
		return true
	}

	// Check groups
	for _, group := range matcher.Groups {
		for _, subjectGroup := range subject.Groups {
			if group == subjectGroup {
				return true
			}
		}
	}

	// Check roles
	for _, role := range matcher.Roles {
		for _, subjectRole := range subject.Roles {
			if role == subjectRole {
				return true
			}
		}
	}

	// Check identity matchers
	for _, im := range matcher.Identities {
		if im.Type != "" && im.Type != subject.Type {
			continue
		}
		if im.ID != "" && im.ID != subject.ID.String() {
			continue
		}
		return true
	}

	return false
}

// matchesResource checks if the resource matches
func (p *Policy) matchesResource(matcher ResourceMatcher, resource PolicyResource) bool {
	if matcher.Any {
		return true
	}

	// Check types
	if len(matcher.Types) > 0 {
		typeMatched := false
		for _, t := range matcher.Types {
			if t == resource.Type {
				typeMatched = true
				break
			}
		}
		if !typeMatched {
			return false
		}
	}

	// Check IDs
	if len(matcher.IDs) > 0 {
		idMatched := false
		for _, id := range matcher.IDs {
			if id == resource.ID {
				idMatched = true
				break
			}
		}
		if !idMatched {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition
func (p *Policy) evaluateCondition(condition Condition, req PolicyEvaluationRequest) bool {
	var value interface{}

	switch condition.Type {
	case ConditionTypeContext:
		value = p.getContextValue(condition.Field, req.Context)
	case ConditionTypeTime:
		value = p.getTimeValue(condition.Field, req.Context.Time)
	case ConditionTypeSubject:
		value = p.getSubjectValue(condition.Field, req.Subject)
	case ConditionTypeResource:
		value = p.getResourceValue(condition.Field, req.Resource)
	}

	result := p.compareValues(condition.Operator, value, condition.Value)
	if condition.Negate {
		return !result
	}
	return result
}

func (p *Policy) getContextValue(field string, ctx PolicyContext) interface{} {
	switch field {
	case "source_ip":
		return ctx.SourceIP
	case "mfa_verified":
		return ctx.MFAVerified
	case "device_posture":
		return ctx.DevicePosture
	case "change_ticket.exists":
		return ctx.ChangeTicket != nil
	case "change_ticket.status":
		if ctx.ChangeTicket != nil {
			return ctx.ChangeTicket.Status
		}
		return ""
	case "emergency.declared":
		if ctx.Emergency != nil {
			return ctx.Emergency.Declared
		}
		return false
	default:
		if ctx.Custom != nil {
			return ctx.Custom[field]
		}
		return nil
	}
}

func (p *Policy) getTimeValue(field string, t time.Time) interface{} {
	switch field {
	case "hour":
		return t.Hour()
	case "day_of_week":
		return int(t.Weekday())
	case "day_of_month":
		return t.Day()
	case "month":
		return int(t.Month())
	default:
		return nil
	}
}

func (p *Policy) getSubjectValue(field string, subject PolicySubject) interface{} {
	switch field {
	case "type":
		return string(subject.Type)
	case "id":
		return subject.ID.String()
	default:
		if subject.Attributes != nil {
			return subject.Attributes[field]
		}
		return nil
	}
}

func (p *Policy) getResourceValue(field string, resource PolicyResource) interface{} {
	switch field {
	case "type":
		return resource.Type
	case "id":
		return resource.ID
	default:
		if resource.Attributes != nil {
			return resource.Attributes[field]
		}
		return nil
	}
}

func (p *Policy) compareValues(op ConditionOperator, actual, expected interface{}) bool {
	switch op {
	case ConditionOpEquals:
		return compareEqual(actual, expected)
	case ConditionOpNotEquals:
		return !compareEqual(actual, expected)
	case ConditionOpIn:
		return containsValue(expected, actual)
	case ConditionOpNotIn:
		return !containsValue(expected, actual)
	case ConditionOpExists:
		return actual != nil
	case ConditionOpGreater, ConditionOpGreaterEq, ConditionOpLess, ConditionOpLessEq:
		return compareNumeric(op, actual, expected)
	default:
		return false
	}
}

func compareEqual(a, b interface{}) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return string(aJSON) == string(bJSON)
}

func containsValue(container, value interface{}) bool {
	arr, ok := container.([]interface{})
	if !ok {
		return false
	}
	for _, item := range arr {
		if compareEqual(item, value) {
			return true
		}
	}
	return false
}

func compareNumeric(op ConditionOperator, actual, expected interface{}) bool {
	aFloat, aOk := toFloat64(actual)
	eFloat, eOk := toFloat64(expected)
	if !aOk || !eOk {
		return false
	}

	switch op {
	case ConditionOpGreater:
		return aFloat > eFloat
	case ConditionOpGreaterEq:
		return aFloat >= eFloat
	case ConditionOpLess:
		return aFloat < eFloat
	case ConditionOpLessEq:
		return aFloat <= eFloat
	default:
		return false
	}
}

func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case int32:
		return float64(val), true
	default:
		return 0, false
	}
}
