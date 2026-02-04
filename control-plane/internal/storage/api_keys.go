package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"golang.org/x/crypto/bcrypt"
)

// APIKeyStorage defines the interface for API key persistence.
// Keys are loaded from config at startup; this interface provides lookup during requests.
type APIKeyStorage interface {
	// VerifyKey verifies a plain key and returns the APIKey if valid.
	VerifyKey(ctx context.Context, plainKey string) (*types.APIKey, error)

	// UpdateKeyLastUsed updates the last_used_at timestamp.
	UpdateKeyLastUsed(ctx context.Context, id string) error
}

// AccessAuditStorage defines the interface for audit logging.
type AccessAuditStorage interface {
	// LogAccessDecision logs an access decision.
	LogAccessDecision(ctx context.Context, entry types.AccessAuditEntry) error

	// ListAccessAuditEntries returns audit entries with optional filters.
	ListAccessAuditEntries(ctx context.Context, filters AccessAuditFilters) ([]*types.AccessAuditEntry, error)
}

// AccessAuditFilters holds filters for querying audit entries.
type AccessAuditFilters struct {
	APIKeyID    *string `json:"api_key_id,omitempty"`
	TargetAgent *string `json:"target_agent,omitempty"`
	Allowed     *bool   `json:"allowed,omitempty"`
	Limit       int     `json:"limit,omitempty"`
	Offset      int     `json:"offset,omitempty"`
}

// GenerateAPIKey generates a new random API key with prefix.
// The prefix identifies the key type (e.g., "sk" for scoped key).
func GenerateAPIKey(prefix string) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(bytes), nil
}

// HashAPIKey creates a bcrypt hash of an API key.
func HashAPIKey(plainKey string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainKey), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyAPIKeyHash verifies a plain key against a bcrypt hash.
func VerifyAPIKeyHash(plainKey, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainKey)) == nil
}

// GenerateKeyID generates a unique key ID.
func GenerateKeyID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return "key_" + hex.EncodeToString(bytes)
}
