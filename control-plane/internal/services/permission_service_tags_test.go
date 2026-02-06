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

	agent := &types.AgentNode{
		ID: "agent-a",
		Metadata: types.AgentMetadata{
			Deployment: &types.DeploymentMetadata{
				Tags: map[string]string{"role": "admin"},
			},
		},
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
