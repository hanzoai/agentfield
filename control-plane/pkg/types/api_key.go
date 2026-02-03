package types

import (
	"strings"
	"time"
)

// APIKey represents an authentication key with optional scope restrictions.
type APIKey struct {
	ID      string `json:"id" db:"id"`
	Name    string `json:"name" db:"name"`
	KeyHash string `json:"-" db:"key_hash"` // bcrypt hash, never exposed in JSON

	// Scopes define what tags this key can access.
	// Empty slice or ["*"] = super key (full access)
	// ["finance", "shared"] = individual tags
	// ["finance*"] = wildcard prefix matching
	// ["@payment-workflow"] = scope group reference (expanded at runtime)
	Scopes []string `json:"scopes" db:"scopes"`

	// ExpandedScopes is populated at runtime after resolving @group references
	ExpandedScopes []string `json:"-" db:"-"`

	// Metadata
	Description string     `json:"description,omitempty" db:"description"`
	Enabled     bool       `json:"enabled" db:"enabled"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

// ScopeGroup defines a named group of tags for workflow-level access.
type ScopeGroup struct {
	Name        string   `json:"name" yaml:"name"`
	Tags        []string `json:"tags" yaml:"tags"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
}

// IsSuperKey returns true if this key has unrestricted access.
func (k *APIKey) IsSuperKey() bool {
	if len(k.Scopes) == 0 {
		return true
	}
	if len(k.Scopes) == 1 && k.Scopes[0] == "*" {
		return true
	}
	return false
}

// IsExpired returns true if the key has expired.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// ExpandScopes resolves @group references and populates ExpandedScopes.
func (k *APIKey) ExpandScopes(groups map[string]ScopeGroup) {
	expanded := make([]string, 0)
	for _, scope := range k.Scopes {
		if strings.HasPrefix(scope, "@") {
			groupName := strings.TrimPrefix(scope, "@")
			if group, ok := groups[groupName]; ok {
				expanded = append(expanded, group.Tags...)
			}
		} else {
			expanded = append(expanded, scope)
		}
	}
	k.ExpandedScopes = expanded
}

// GetEffectiveScopes returns expanded scopes if available, otherwise raw scopes.
func (k *APIKey) GetEffectiveScopes() []string {
	if len(k.ExpandedScopes) > 0 {
		return k.ExpandedScopes
	}
	return k.Scopes
}

// CanAccess checks if this key can access an agent with the given tags.
func (k *APIKey) CanAccess(agentTags []string) bool {
	if k.IsSuperKey() {
		return true
	}

	effectiveScopes := k.GetEffectiveScopes()
	for _, scope := range effectiveScopes {
		for _, tag := range agentTags {
			if MatchesTagPattern(scope, tag) {
				return true
			}
		}
	}
	return false
}

// MatchesTagPattern checks if a scope pattern matches a tag.
// Supports:
//   - Exact match: "finance" matches "finance"
//   - Prefix wildcard: "finance*" matches "finance", "finance-internal"
//   - Suffix wildcard: "*-internal" matches "finance-internal", "hr-internal"
//   - Full wildcard: "*" matches anything
func MatchesTagPattern(pattern, tag string) bool {
	if pattern == "*" {
		return true
	}

	// Prefix wildcard: "finance*"
	if strings.HasSuffix(pattern, "*") && !strings.HasPrefix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(tag, prefix)
	}

	// Suffix wildcard: "*-internal"
	if strings.HasPrefix(pattern, "*") && !strings.HasSuffix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(tag, suffix)
	}

	// Exact match
	return pattern == tag
}

// APIKeyCreateRequest represents a request to create a new API key.
type APIKeyCreateRequest struct {
	Name        string     `json:"name" binding:"required"`
	Scopes      []string   `json:"scopes"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// APIKeyResponse represents an API key in responses (no sensitive data).
type APIKeyResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes"`
	Description string     `json:"description,omitempty"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// ToResponse converts an APIKey to a safe response format.
func (k *APIKey) ToResponse() APIKeyResponse {
	return APIKeyResponse{
		ID:          k.ID,
		Name:        k.Name,
		Scopes:      k.Scopes,
		Description: k.Description,
		Enabled:     k.Enabled,
		CreatedAt:   k.CreatedAt,
		ExpiresAt:   k.ExpiresAt,
		LastUsedAt:  k.LastUsedAt,
	}
}

// AccessDecision represents the result of an access check.
type AccessDecision struct {
	Allowed    bool     `json:"allowed"`
	KeyScopes  []string `json:"key_scopes"`
	AgentTags  []string `json:"agent_tags"`
	MatchedOn  string   `json:"matched_on,omitempty"`  // Which scope/tag pair matched
	DenyReason string   `json:"deny_reason,omitempty"` // Why access was denied
}

// AccessAuditEntry represents a logged access decision.
type AccessAuditEntry struct {
	ID             int64     `json:"id" db:"id"`
	Timestamp      time.Time `json:"timestamp" db:"timestamp"`
	APIKeyID       string    `json:"api_key_id" db:"api_key_id"`
	APIKeyName     string    `json:"api_key_name" db:"api_key_name"`
	TargetAgent    string    `json:"target_agent" db:"target_agent"`
	TargetReasoner string    `json:"target_reasoner,omitempty" db:"target_reasoner"`
	AgentTags      []string  `json:"agent_tags" db:"agent_tags"`
	KeyScopes      []string  `json:"key_scopes" db:"key_scopes"`
	Allowed        bool      `json:"allowed" db:"allowed"`
	DenyReason     string    `json:"deny_reason,omitempty" db:"deny_reason"`
}
