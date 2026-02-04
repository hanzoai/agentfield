package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// mockAuditStorage is a test double for access audit storage.
type mockAuditStorage struct {
	mu      sync.Mutex
	entries []types.AccessAuditEntry
	err     error
}

func (m *mockAuditStorage) LogAccessDecision(ctx context.Context, entry types.AccessAuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditStorage) ListAccessAuditEntries(ctx context.Context, filters storage.AccessAuditFilters) ([]*types.AccessAuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	result := make([]*types.AccessAuditEntry, len(m.entries))
	for i := range m.entries {
		result[i] = &m.entries[i]
	}
	return result, nil
}

func (m *mockAuditStorage) getEntries() []types.AccessAuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]types.AccessAuditEntry{}, m.entries...)
}

func TestAccessControlService_CheckAccess_SuperKey(t *testing.T) {
	tests := []struct {
		name      string
		keyScopes []string
		agentTags []string
	}{
		{
			name:      "empty scopes is super key",
			keyScopes: []string{},
			agentTags: []string{"finance", "internal"},
		},
		{
			name:      "nil scopes is super key",
			keyScopes: nil,
			agentTags: []string{"finance", "internal"},
		},
		{
			name:      "wildcard only is super key",
			keyScopes: []string{"*"},
			agentTags: []string{"finance", "internal"},
		},
		{
			name:      "super key can access empty tags",
			keyScopes: []string{},
			agentTags: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewAccessControlService(false, nil, nil)

			decision := svc.CheckAccess(
				context.Background(),
				"key-1", "test-key",
				tt.keyScopes,
				"agent-1", "",
				tt.agentTags,
			)

			assert.True(t, decision.Allowed, "super key should always be allowed")
			assert.Equal(t, "*", decision.MatchedOn, "super key should match on *")
			assert.Empty(t, decision.DenyReason)
		})
	}
}

func TestAccessControlService_CheckAccess_ExactMatch(t *testing.T) {
	svc := NewAccessControlService(false, nil, nil)

	tests := []struct {
		name        string
		keyScopes   []string
		agentTags   []string
		expectAllow bool
		matchedOn   string
	}{
		{
			name:        "exact tag match",
			keyScopes:   []string{"finance"},
			agentTags:   []string{"finance"},
			expectAllow: true,
			matchedOn:   "finance -> finance",
		},
		{
			name:        "one of multiple scopes matches",
			keyScopes:   []string{"hr", "finance"},
			agentTags:   []string{"finance"},
			expectAllow: true,
			matchedOn:   "finance -> finance",
		},
		{
			name:        "one of multiple tags matches",
			keyScopes:   []string{"finance"},
			agentTags:   []string{"hr", "finance"},
			expectAllow: true,
			matchedOn:   "finance -> finance",
		},
		{
			name:        "no match",
			keyScopes:   []string{"finance"},
			agentTags:   []string{"hr"},
			expectAllow: false,
		},
		{
			name:        "empty tags denied",
			keyScopes:   []string{"finance"},
			agentTags:   []string{},
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := svc.CheckAccess(
				context.Background(),
				"key-1", "test-key",
				tt.keyScopes,
				"agent-1", "",
				tt.agentTags,
			)

			assert.Equal(t, tt.expectAllow, decision.Allowed)
			if tt.expectAllow {
				assert.Equal(t, tt.matchedOn, decision.MatchedOn)
				assert.Empty(t, decision.DenyReason)
			} else {
				assert.Equal(t, "no matching tags", decision.DenyReason)
			}
		})
	}
}

func TestAccessControlService_CheckAccess_WildcardPatterns(t *testing.T) {
	svc := NewAccessControlService(false, nil, nil)

	tests := []struct {
		name        string
		keyScopes   []string
		agentTags   []string
		expectAllow bool
		matchedOn   string
	}{
		{
			name:        "prefix wildcard matches",
			keyScopes:   []string{"finance*"},
			agentTags:   []string{"finance-internal"},
			expectAllow: true,
			matchedOn:   "finance* -> finance-internal",
		},
		{
			name:        "prefix wildcard matches exact",
			keyScopes:   []string{"finance*"},
			agentTags:   []string{"finance"},
			expectAllow: true,
			matchedOn:   "finance* -> finance",
		},
		{
			name:        "suffix wildcard matches",
			keyScopes:   []string{"*-internal"},
			agentTags:   []string{"finance-internal"},
			expectAllow: true,
			matchedOn:   "*-internal -> finance-internal",
		},
		{
			name:        "suffix wildcard matches exact suffix",
			keyScopes:   []string{"*-internal"},
			agentTags:   []string{"hr-internal"},
			expectAllow: true,
			matchedOn:   "*-internal -> hr-internal",
		},
		{
			name:        "prefix wildcard no match",
			keyScopes:   []string{"finance*"},
			agentTags:   []string{"hr-internal"},
			expectAllow: false,
		},
		{
			name:        "suffix wildcard no match",
			keyScopes:   []string{"*-external"},
			agentTags:   []string{"finance-internal"},
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := svc.CheckAccess(
				context.Background(),
				"key-1", "test-key",
				tt.keyScopes,
				"agent-1", "",
				tt.agentTags,
			)

			assert.Equal(t, tt.expectAllow, decision.Allowed)
			if tt.expectAllow {
				assert.Equal(t, tt.matchedOn, decision.MatchedOn)
			}
		})
	}
}

func TestAccessControlService_CheckAccess_ScopeGroups(t *testing.T) {
	scopeGroups := map[string]types.ScopeGroup{
		"payment-workflow": {
			Name: "payment-workflow",
			Tags: []string{"payment", "billing", "finance"},
		},
		"admin-team": {
			Name: "admin-team",
			Tags: []string{"admin", "superuser"},
		},
	}

	svc := NewAccessControlService(false, nil, scopeGroups)

	tests := []struct {
		name        string
		keyScopes   []string
		agentTags   []string
		expectAllow bool
	}{
		{
			name:        "scope group expanded to match",
			keyScopes:   []string{"@payment-workflow"},
			agentTags:   []string{"billing"},
			expectAllow: true,
		},
		{
			name:        "scope group no match",
			keyScopes:   []string{"@payment-workflow"},
			agentTags:   []string{"hr"},
			expectAllow: false,
		},
		{
			name:        "mixed scope group and regular",
			keyScopes:   []string{"@payment-workflow", "hr"},
			agentTags:   []string{"hr"},
			expectAllow: true,
		},
		{
			name:        "unknown scope group kept as-is",
			keyScopes:   []string{"@unknown-group"},
			agentTags:   []string{"@unknown-group"}, // Treated as literal
			expectAllow: true,
		},
		{
			name:        "unknown scope group no match",
			keyScopes:   []string{"@unknown-group"},
			agentTags:   []string{"unknown-group"},
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := svc.CheckAccess(
				context.Background(),
				"key-1", "test-key",
				tt.keyScopes,
				"agent-1", "",
				tt.agentTags,
			)

			assert.Equal(t, tt.expectAllow, decision.Allowed)
		})
	}
}

func TestAccessControlService_CheckAccess_AuditLogging(t *testing.T) {
	mockStorage := &mockAuditStorage{}
	svc := NewAccessControlService(true, mockStorage, nil)

	// Make a decision that should be logged
	decision := svc.CheckAccess(
		context.Background(),
		"key-123", "finance-key",
		[]string{"finance"},
		"payment-agent", "process-payment",
		[]string{"finance", "billing"},
	)

	assert.True(t, decision.Allowed)

	// Wait for async logging
	time.Sleep(50 * time.Millisecond)

	entries := mockStorage.getEntries()
	require.Len(t, entries, 1)
	entry := entries[0]

	assert.Equal(t, "key-123", entry.APIKeyID)
	assert.Equal(t, "finance-key", entry.APIKeyName)
	assert.Equal(t, "payment-agent", entry.TargetAgent)
	assert.Equal(t, "process-payment", entry.TargetReasoner)
	assert.True(t, entry.Allowed)
	assert.Equal(t, []string{"finance"}, entry.KeyScopes)
	assert.Equal(t, []string{"finance", "billing"}, entry.AgentTags)
}

func TestAccessControlService_CheckAccess_AuditLogging_Denied(t *testing.T) {
	mockStorage := &mockAuditStorage{}
	svc := NewAccessControlService(true, mockStorage, nil)

	decision := svc.CheckAccess(
		context.Background(),
		"key-456", "hr-key",
		[]string{"hr"},
		"finance-agent", "",
		[]string{"finance"},
	)

	assert.False(t, decision.Allowed)
	assert.Equal(t, "no matching tags", decision.DenyReason)

	// Wait for async logging
	time.Sleep(50 * time.Millisecond)

	entries := mockStorage.getEntries()
	require.Len(t, entries, 1)
	entry := entries[0]

	assert.False(t, entry.Allowed)
	assert.Equal(t, "no matching tags", entry.DenyReason)
}

func TestAccessControlService_CheckAccess_AuditDisabled(t *testing.T) {
	mockStorage := &mockAuditStorage{}
	svc := NewAccessControlService(false, mockStorage, nil) // Audit disabled

	svc.CheckAccess(
		context.Background(),
		"key-1", "test-key",
		[]string{"finance"},
		"agent-1", "",
		[]string{"finance"},
	)

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Should not have logged
	entries := mockStorage.getEntries()
	assert.Len(t, entries, 0)
}

func TestAccessControlService_CheckAccess_NilAuditStorage(t *testing.T) {
	// Should not panic with nil storage
	svc := NewAccessControlService(true, nil, nil)

	decision := svc.CheckAccess(
		context.Background(),
		"key-1", "test-key",
		[]string{"finance"},
		"agent-1", "",
		[]string{"finance"},
	)

	assert.True(t, decision.Allowed)
}

func TestAccessControlService_FilterAgentsByAccess(t *testing.T) {
	svc := NewAccessControlService(false, nil, nil)

	agents := []*types.AgentNode{
		{
			ID:   "finance-agent",
			Tags: []string{"finance", "internal"},
		},
		{
			ID:   "hr-agent",
			Tags: []string{"hr"},
		},
		{
			ID:   "public-agent",
			Tags: []string{"public"},
		},
	}

	tests := []struct {
		name          string
		keyScopes     []string
		expectedIDs   []string
	}{
		{
			name:          "super key sees all",
			keyScopes:     []string{},
			expectedIDs:   []string{"finance-agent", "hr-agent", "public-agent"},
		},
		{
			name:          "wildcard super key sees all",
			keyScopes:     []string{"*"},
			expectedIDs:   []string{"finance-agent", "hr-agent", "public-agent"},
		},
		{
			name:          "specific scope filters",
			keyScopes:     []string{"finance"},
			expectedIDs:   []string{"finance-agent"},
		},
		{
			name:          "multiple scopes",
			keyScopes:     []string{"finance", "hr"},
			expectedIDs:   []string{"finance-agent", "hr-agent"},
		},
		{
			name:          "wildcard scope",
			keyScopes:     []string{"*-agent"},
			expectedIDs:   []string{}, // Tags don't match *-agent pattern
		},
		{
			name:          "prefix wildcard matches internal",
			keyScopes:     []string{"*internal"},
			expectedIDs:   []string{"finance-agent"},
		},
		{
			name:          "no matching scope",
			keyScopes:     []string{"admin"},
			expectedIDs:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := svc.FilterAgentsByAccess(agents, tt.keyScopes)

			var ids []string
			for _, a := range filtered {
				ids = append(ids, a.ID)
			}

			assert.ElementsMatch(t, tt.expectedIDs, ids)
		})
	}
}

func TestAccessControlService_FilterAgentsByAccess_WithReasonerTags(t *testing.T) {
	svc := NewAccessControlService(false, nil, nil)

	agents := []*types.AgentNode{
		{
			ID:   "multi-agent",
			Tags: []string{"base"},
			Reasoners: []types.ReasonerDefinition{
				{ID: "finance-reasoner", Tags: []string{"finance"}},
				{ID: "hr-reasoner", Tags: []string{"hr"}},
			},
		},
	}

	tests := []struct {
		name        string
		keyScopes   []string
		expectMatch bool
	}{
		{
			name:        "match on base tag",
			keyScopes:   []string{"base"},
			expectMatch: true,
		},
		{
			name:        "match on reasoner tag",
			keyScopes:   []string{"finance"},
			expectMatch: true,
		},
		{
			name:        "match on other reasoner tag",
			keyScopes:   []string{"hr"},
			expectMatch: true,
		},
		{
			name:        "no match",
			keyScopes:   []string{"admin"},
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := svc.FilterAgentsByAccess(agents, tt.keyScopes)

			if tt.expectMatch {
				require.Len(t, filtered, 1)
				assert.Equal(t, "multi-agent", filtered[0].ID)
			} else {
				assert.Len(t, filtered, 0)
			}
		})
	}
}

func TestAccessControlService_FilterAgentsByAccess_WithSkillTags(t *testing.T) {
	svc := NewAccessControlService(false, nil, nil)

	agents := []*types.AgentNode{
		{
			ID: "skill-agent",
			Skills: []types.SkillDefinition{
				{ID: "process-payment", Tags: []string{"payment"}},
			},
		},
	}

	// Match on skill tag
	filtered := svc.FilterAgentsByAccess(agents, []string{"payment"})
	require.Len(t, filtered, 1)

	// No match
	filtered = svc.FilterAgentsByAccess(agents, []string{"admin"})
	assert.Len(t, filtered, 0)
}

func TestAccessControlService_FilterAgentsByAccess_ScopeGroups(t *testing.T) {
	scopeGroups := map[string]types.ScopeGroup{
		"financial": {
			Name: "financial",
			Tags: []string{"finance", "billing", "payment"},
		},
	}

	svc := NewAccessControlService(false, nil, scopeGroups)

	agents := []*types.AgentNode{
		{ID: "finance-agent", Tags: []string{"finance"}},
		{ID: "billing-agent", Tags: []string{"billing"}},
		{ID: "hr-agent", Tags: []string{"hr"}},
	}

	// Scope group should expand and match both financial agents
	filtered := svc.FilterAgentsByAccess(agents, []string{"@financial"})

	var ids []string
	for _, a := range filtered {
		ids = append(ids, a.ID)
	}

	assert.ElementsMatch(t, []string{"finance-agent", "billing-agent"}, ids)
}

func TestGetAgentTags(t *testing.T) {
	tests := []struct {
		name         string
		agent        *types.AgentNode
		expectedTags []string
	}{
		{
			name: "agent tags only",
			agent: &types.AgentNode{
				Tags: []string{"finance", "internal"},
			},
			expectedTags: []string{"finance", "internal"},
		},
		{
			name: "includes reasoner tags",
			agent: &types.AgentNode{
				Tags: []string{"base"},
				Reasoners: []types.ReasonerDefinition{
					{Tags: []string{"reasoner-tag"}},
				},
			},
			expectedTags: []string{"base", "reasoner-tag"},
		},
		{
			name: "includes skill tags",
			agent: &types.AgentNode{
				Tags: []string{"base"},
				Skills: []types.SkillDefinition{
					{Tags: []string{"skill-tag"}},
				},
			},
			expectedTags: []string{"base", "skill-tag"},
		},
		{
			name: "deduplicates tags",
			agent: &types.AgentNode{
				Tags: []string{"shared"},
				Reasoners: []types.ReasonerDefinition{
					{Tags: []string{"shared"}},
				},
				Skills: []types.SkillDefinition{
					{Tags: []string{"shared"}},
				},
			},
			expectedTags: []string{"shared"},
		},
		{
			name: "empty agent",
			agent: &types.AgentNode{
				Tags: nil,
			},
			expectedTags: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags := GetAgentTags(tt.agent)
			assert.ElementsMatch(t, tt.expectedTags, tags)
		})
	}
}

func TestIsSuperKeyScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		isSuper  bool
	}{
		{"empty scopes", []string{}, true},
		{"nil scopes", nil, true},
		{"wildcard only", []string{"*"}, true},
		{"single regular scope", []string{"finance"}, false},
		{"multiple scopes", []string{"finance", "hr"}, false},
		{"wildcard with others", []string{"*", "finance"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isSuper, isSuperKeyScopes(tt.scopes))
		})
	}
}

func TestCanAccessWithScopes(t *testing.T) {
	tests := []struct {
		name      string
		scopes    []string
		tags      []string
		canAccess bool
	}{
		{"super key empty", []string{}, []string{"any"}, true},
		{"super key wildcard", []string{"*"}, []string{"any"}, true},
		{"exact match", []string{"finance"}, []string{"finance"}, true},
		{"no match", []string{"finance"}, []string{"hr"}, false},
		{"prefix match", []string{"finance*"}, []string{"finance-internal"}, true},
		{"suffix match", []string{"*-internal"}, []string{"finance-internal"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.canAccess, canAccessWithScopes(tt.scopes, tt.tags))
		})
	}
}

func TestExpandScopes(t *testing.T) {
	scopeGroups := map[string]types.ScopeGroup{
		"financial": {
			Tags: []string{"finance", "billing"},
		},
		"admin": {
			Tags: []string{"admin", "superuser"},
		},
	}

	svc := NewAccessControlService(false, nil, scopeGroups)

	tests := []struct {
		name     string
		scopes   []string
		expected []string
	}{
		{
			name:     "regular scopes unchanged",
			scopes:   []string{"finance", "hr"},
			expected: []string{"finance", "hr"},
		},
		{
			name:     "group expanded",
			scopes:   []string{"@financial"},
			expected: []string{"finance", "billing"},
		},
		{
			name:     "mixed expansion",
			scopes:   []string{"hr", "@financial"},
			expected: []string{"hr", "finance", "billing"},
		},
		{
			name:     "unknown group kept",
			scopes:   []string{"@unknown"},
			expected: []string{"@unknown"},
		},
		{
			name:     "empty scopes",
			scopes:   []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expanded := svc.expandScopes(tt.scopes)
			assert.Equal(t, tt.expected, expanded)
		})
	}
}

func TestExpandScopes_NilScopeGroups(t *testing.T) {
	svc := NewAccessControlService(false, nil, nil)

	scopes := []string{"@group", "regular"}
	expanded := svc.expandScopes(scopes)

	// With nil scope groups, scopes are returned as-is
	assert.Equal(t, []string{"@group", "regular"}, expanded)
}

func TestAccessDecision_Fields(t *testing.T) {
	svc := NewAccessControlService(false, nil, nil)

	// Test allowed decision fields
	allowed := svc.CheckAccess(
		context.Background(),
		"key-1", "test-key",
		[]string{"finance"},
		"agent", "",
		[]string{"finance"},
	)

	assert.True(t, allowed.Allowed)
	assert.Equal(t, []string{"finance"}, allowed.KeyScopes)
	assert.Equal(t, []string{"finance"}, allowed.AgentTags)
	assert.NotEmpty(t, allowed.MatchedOn)
	assert.Empty(t, allowed.DenyReason)

	// Test denied decision fields
	denied := svc.CheckAccess(
		context.Background(),
		"key-1", "test-key",
		[]string{"hr"},
		"agent", "",
		[]string{"finance"},
	)

	assert.False(t, denied.Allowed)
	assert.Equal(t, []string{"hr"}, denied.KeyScopes)
	assert.Equal(t, []string{"finance"}, denied.AgentTags)
	assert.Empty(t, denied.MatchedOn)
	assert.Equal(t, "no matching tags", denied.DenyReason)
}
