package services

import (
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestCanonicalTagMatching_ExactAndWildcard(t *testing.T) {
	svc := &PermissionService{
		config: &PermissionConfig{Enabled: true},
		rules: []*types.ProtectedAgentRule{
			{
				PatternType: types.PatternTypeTag,
				Pattern:     "admin",
				Enabled:     true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			{
				PatternType: types.PatternTypeTagPattern,
				Pattern:     "adm*",
				Enabled:     true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
	}

	// Use approved tags (not deployment metadata, which are self-asserted and
	// excluded from canonical authorization tags for security)
	agent := &types.AgentNode{
		ID:           "agent-a",
		ApprovedTags: []string{"admin"},
	}
	canonicalTags := CanonicalAgentTags(agent)

	assert.Contains(t, canonicalTags, "admin")
	assert.True(t, svc.IsAgentProtected(agent.ID, canonicalTags))
}

func TestCanonicalTagMatching_LegacyPatternStillMatchesPlainTag(t *testing.T) {
	svc := &PermissionService{
		config: &PermissionConfig{Enabled: true},
		rules: []*types.ProtectedAgentRule{
			{
				PatternType: types.PatternTypeTag,
				Pattern:     "role:admin",
				Enabled:     true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
	}

	assert.True(t, svc.IsAgentProtected("agent-a", []string{"admin"}))
}
