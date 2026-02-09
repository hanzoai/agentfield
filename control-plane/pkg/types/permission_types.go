package types

import (
	"encoding/json"
	"time"
)

// PermissionStatus represents the status of a permission approval.
type PermissionStatus string

const (
	PermissionStatusPending  PermissionStatus = "pending"
	PermissionStatusApproved PermissionStatus = "approved"
	PermissionStatusRejected PermissionStatus = "rejected"
	PermissionStatusRevoked  PermissionStatus = "revoked"
	PermissionStatusExpired  PermissionStatus = "expired"
)

// PermissionApproval represents a permission approval record.
// This tracks whether a caller agent has been approved to call a target agent.
type PermissionApproval struct {
	ID            int64            `json:"id" db:"id"`
	CallerDID     string           `json:"caller_did" db:"caller_did"`
	TargetDID     string           `json:"target_did" db:"target_did"`
	CallerAgentID string           `json:"caller_agent_id" db:"caller_agent_id"`
	TargetAgentID string           `json:"target_agent_id" db:"target_agent_id"`
	Status        PermissionStatus `json:"status" db:"status"`
	ApprovedBy    *string          `json:"approved_by,omitempty" db:"approved_by"`
	ApprovedAt    *time.Time       `json:"approved_at,omitempty" db:"approved_at"`
	RejectedBy    *string          `json:"rejected_by,omitempty" db:"rejected_by"`
	RejectedAt    *time.Time       `json:"rejected_at,omitempty" db:"rejected_at"`
	RevokedBy     *string          `json:"revoked_by,omitempty" db:"revoked_by"`
	RevokedAt     *time.Time       `json:"revoked_at,omitempty" db:"revoked_at"`
	ExpiresAt     *time.Time       `json:"expires_at,omitempty" db:"expires_at"`
	Reason        *string          `json:"reason,omitempty" db:"reason"`
	CreatedAt     time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at" db:"updated_at"`
}

// IsValid returns true if the approval is in an active, non-expired state.
func (p *PermissionApproval) IsValid() bool {
	if p.Status != PermissionStatusApproved {
		return false
	}
	if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
		return false
	}
	return true
}

// EffectiveStatus returns the display status accounting for expiration.
// If the DB status is "approved" but the permission has expired, returns "expired".
func (p *PermissionApproval) EffectiveStatus() PermissionStatus {
	if p.Status == PermissionStatusApproved && p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
		return PermissionStatusExpired
	}
	return p.Status
}

// MarshalJSON adds an effective_status field to the JSON output that accounts for expiration.
func (p PermissionApproval) MarshalJSON() ([]byte, error) {
	type Alias PermissionApproval
	return json.Marshal(&struct {
		Alias
		EffectiveStatus PermissionStatus `json:"effective_status"`
	}{
		Alias:           (Alias)(p),
		EffectiveStatus: p.EffectiveStatus(),
	})
}

// PermissionRequest represents a request to create a new permission.
type PermissionRequest struct {
	CallerDID     string `json:"caller_did" binding:"required"`
	TargetDID     string `json:"target_did" binding:"required"`
	CallerAgentID string `json:"caller_agent_id" binding:"required"`
	TargetAgentID string `json:"target_agent_id" binding:"required"`
	Reason        string `json:"reason,omitempty"`
}

// PermissionApproveRequest represents a request to approve a permission.
type PermissionApproveRequest struct {
	DurationHours *int   `json:"duration_hours,omitempty"` // nil = permanent
	Reason        string `json:"reason,omitempty"`
}

// PermissionRejectRequest represents a request to reject a permission.
type PermissionRejectRequest struct {
	Reason string `json:"reason,omitempty"`
}

// PermissionRevokeRequest represents a request to revoke a permission.
type PermissionRevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// PermissionCheck represents the result of checking permission between two agents.
type PermissionCheck struct {
	RequiresPermission bool             `json:"requires_permission"`
	HasValidApproval   bool             `json:"has_valid_approval"`
	ApprovalStatus     PermissionStatus `json:"approval_status,omitempty"`
	ApprovalID         *int64           `json:"approval_id,omitempty"`
	ExpiresAt          *time.Time       `json:"expires_at,omitempty"`
	VC                 string           `json:"vc,omitempty"` // Signed VC if approved
}

// ProtectedAgentPatternType defines the type of pattern for protected agent rules.
type ProtectedAgentPatternType string

const (
	PatternTypeTag        ProtectedAgentPatternType = "tag"
	PatternTypeTagPattern ProtectedAgentPatternType = "tag_pattern"
	PatternTypeAgentID    ProtectedAgentPatternType = "agent_id"
)

// ProtectedAgentRule defines a rule for which agents require permission to call.
type ProtectedAgentRule struct {
	ID          int64                     `json:"id" db:"id"`
	PatternType ProtectedAgentPatternType `json:"pattern_type" db:"pattern_type"`
	Pattern     string                    `json:"pattern" db:"pattern"`
	Description *string                   `json:"description,omitempty" db:"description"`
	Enabled     bool                      `json:"enabled" db:"enabled"`
	CreatedAt   time.Time                 `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at" db:"updated_at"`
}

// ProtectedAgentRuleRequest represents a request to create a protected agent rule.
type ProtectedAgentRuleRequest struct {
	PatternType ProtectedAgentPatternType `json:"pattern_type" binding:"required"`
	Pattern     string                    `json:"pattern" binding:"required"`
	Description string                    `json:"description,omitempty"`
}

// AccessPolicy defines a tag-based authorization policy for cross-agent calls.
type AccessPolicy struct {
	ID             int64                        `json:"id" db:"id"`
	Name           string                       `json:"name" db:"name"`
	CallerTags     []string                     `json:"caller_tags"`
	TargetTags     []string                     `json:"target_tags"`
	AllowFunctions []string                     `json:"allow_functions"`
	DenyFunctions  []string                     `json:"deny_functions"`
	Constraints    map[string]AccessConstraint  `json:"constraints,omitempty"`
	Action         string                       `json:"action" db:"action"`       // "allow" or "deny"
	Priority       int                          `json:"priority" db:"priority"`
	Enabled        bool                         `json:"enabled" db:"enabled"`
	Description    *string                      `json:"description,omitempty" db:"description"`
	CreatedAt      time.Time                    `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time                    `json:"updated_at" db:"updated_at"`
}

// AccessConstraint defines a parameter constraint for a policy.
type AccessConstraint struct {
	Operator string `json:"operator"` // "<=", ">=", "==", "!=", "<", ">"
	Value    any    `json:"value"`
}

// AccessPolicyRequest represents a request to create or update an access policy.
type AccessPolicyRequest struct {
	Name           string                       `json:"name" binding:"required"`
	CallerTags     []string                     `json:"caller_tags" binding:"required"`
	TargetTags     []string                     `json:"target_tags" binding:"required"`
	AllowFunctions []string                     `json:"allow_functions,omitempty"`
	DenyFunctions  []string                     `json:"deny_functions,omitempty"`
	Constraints    map[string]AccessConstraint  `json:"constraints,omitempty"`
	Action         string                       `json:"action" binding:"required"`
	Priority       int                          `json:"priority,omitempty"`
	Description    string                       `json:"description,omitempty"`
}

// PolicyEvaluationResult represents the outcome of evaluating access policies.
type PolicyEvaluationResult struct {
	Allowed    bool   `json:"allowed"`
	Matched    bool   `json:"matched"`      // true if a policy matched
	PolicyName string `json:"policy_name"`  // which policy matched
	PolicyID   int64  `json:"policy_id"`
	Reason     string `json:"reason"`       // why allow/deny
}

// AccessPolicyListResponse represents the response for listing access policies.
type AccessPolicyListResponse struct {
	Policies []*AccessPolicy `json:"policies"`
	Total    int             `json:"total"`
}

// PermissionVC represents a verifiable credential for a permission grant.
type PermissionVC struct {
	VCID       string          `json:"vc_id" db:"vc_id"`
	CallerDID  string          `json:"caller_did" db:"caller_did"`
	TargetDID  string          `json:"target_did" db:"target_did"`
	ApprovalID int64           `json:"approval_id" db:"approval_id"`
	VCDocument json.RawMessage `json:"vc_document" db:"vc_document"`
	Signature  string          `json:"signature" db:"signature"`
	IssuedAt   time.Time       `json:"issued_at" db:"issued_at"`
	ExpiresAt  *time.Time      `json:"expires_at,omitempty" db:"expires_at"`
	RevokedAt  *time.Time      `json:"revoked_at,omitempty" db:"revoked_at"`
}

// PermissionVCCredentialSubject represents the credentialSubject of a PermissionVC.
type PermissionVCCredentialSubject struct {
	Caller     PermissionVCAgent `json:"caller"`
	Target     PermissionVCAgent `json:"target"`
	Permission string            `json:"permission"` // "call"
	ApprovedBy string            `json:"approved_by,omitempty"`
	ApprovedAt string            `json:"approved_at,omitempty"`
}

// PermissionVCAgent represents an agent reference in a PermissionVC.
type PermissionVCAgent struct {
	DID     string `json:"did"`
	AgentID string `json:"agent_id"`
}

// PermissionVCDocument represents the full W3C VC document for a permission.
type PermissionVCDocument struct {
	Context           []string                      `json:"@context"`
	Type              []string                      `json:"type"`
	ID                string                        `json:"id"`
	Issuer            string                        `json:"issuer"`
	IssuanceDate      string                        `json:"issuanceDate"`
	ExpirationDate    string                        `json:"expirationDate,omitempty"`
	CredentialSubject PermissionVCCredentialSubject `json:"credentialSubject"`
	Proof             *VCProof                      `json:"proof,omitempty"`
}

// AgentTagVCDocument is a W3C Verifiable Credential certifying an agent's approved tags.
// Issued when an admin approves an agent's tags. Verified at call time.
type AgentTagVCDocument struct {
	Context           []string                    `json:"@context"`
	Type              []string                    `json:"type"`
	ID                string                      `json:"id"`
	Issuer            string                      `json:"issuer"`
	IssuanceDate      string                      `json:"issuanceDate"`
	ExpirationDate    string                      `json:"expirationDate,omitempty"`
	CredentialSubject AgentTagVCCredentialSubject  `json:"credentialSubject"`
	Proof             *VCProof                    `json:"proof,omitempty"`
}

// AgentTagVCCredentialSubject is the credentialSubject of an AgentTagVC.
type AgentTagVCCredentialSubject struct {
	ID          string                `json:"id"`        // Agent's DID
	AgentID     string                `json:"agent_id"`
	Permissions AgentTagVCPermissions `json:"permissions"`
	ApprovedBy  string                `json:"approved_by,omitempty"`
	ApprovedAt  string                `json:"approved_at,omitempty"`
}

// AgentTagVCPermissions contains the approved tags and callee permissions.
type AgentTagVCPermissions struct {
	Tags           []string `json:"tags"`             // Approved tags
	AllowedCallees []string `json:"allowed_callees"`  // ["*"] = policy decides
}

// AgentTagVCRecord is the DB record for a stored Agent Tag VC.
type AgentTagVCRecord struct {
	ID         int64      `json:"id"`
	AgentID    string     `json:"agent_id"`
	AgentDID   string     `json:"agent_did"`
	VCID       string     `json:"vc_id"`
	VCDocument string     `json:"vc_document"`
	Signature  string     `json:"signature"`
	IssuedAt   time.Time  `json:"issued_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// PermissionListResponse represents the response for listing permissions.
type PermissionListResponse struct {
	Permissions []*PermissionApproval `json:"permissions"`
	Total       int                   `json:"total"`
}

// ProtectedAgentListResponse represents the response for listing protected agent rules.
type ProtectedAgentListResponse struct {
	Rules []*ProtectedAgentRule `json:"rules"`
	Total int                   `json:"total"`
}

// TagApprovalRequest represents a request to approve an agent's tags.
type TagApprovalRequest struct {
	ApprovedTags []string            `json:"approved_tags" binding:"required"`
	SkillTags    map[string][]string `json:"skill_tags,omitempty"`
	ReasonerTags map[string][]string `json:"reasoner_tags,omitempty"`
	Reason       string              `json:"reason,omitempty"`
}

// TagRejectionRequest represents a request to reject an agent's tags.
type TagRejectionRequest struct {
	Reason string `json:"reason,omitempty"`
}

// PendingAgentResponse represents the response for a pending agent's tag info.
type PendingAgentResponse struct {
	AgentID      string   `json:"agent_id"`
	ProposedTags []string `json:"proposed_tags"`
	ApprovedTags []string `json:"approved_tags,omitempty"`
	Status       string   `json:"status"`
	RegisteredAt string   `json:"registered_at"`
}
