package types

import (
	"testing"
	"time"
)

func TestMatchesTagPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		tag      string
		expected bool
	}{
		// Exact match
		{"exact match", "finance", "finance", true},
		{"exact no match", "finance", "hr", false},
		{"exact empty tag", "finance", "", false},
		{"exact empty pattern", "", "finance", false},

		// Prefix wildcard
		{"prefix wildcard match exact", "finance*", "finance", true},
		{"prefix wildcard match suffix", "finance*", "finance-internal", true},
		{"prefix wildcard match longer", "finance*", "finance-pci-compliant", true},
		{"prefix wildcard no match", "finance*", "hr", false},
		{"prefix wildcard no match partial", "finance*", "fin", false},

		// Suffix wildcard
		{"suffix wildcard match", "*-internal", "finance-internal", true},
		{"suffix wildcard match hr", "*-internal", "hr-internal", true},
		{"suffix wildcard no match", "*-internal", "finance", false},
		{"suffix wildcard no match different suffix", "*-internal", "finance-external", false},

		// Full wildcard
		{"full wildcard matches anything", "*", "anything", true},
		{"full wildcard matches empty", "*", "", true},
		{"full wildcard matches special", "*", "finance-pci-internal", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesTagPattern(tt.pattern, tt.tag)
			if result != tt.expected {
				t.Errorf("MatchesTagPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.tag, result, tt.expected)
			}
		})
	}
}

func TestAPIKey_IsSuperKey(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		expected bool
	}{
		{"empty scopes is super key", []string{}, true},
		{"nil scopes is super key", nil, true},
		{"wildcard only is super key", []string{"*"}, true},
		{"single scope not super key", []string{"finance"}, false},
		{"multiple scopes not super key", []string{"finance", "hr"}, false},
		{"wildcard with others not super key", []string{"*", "finance"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Scopes: tt.scopes}
			result := key.IsSuperKey()
			if result != tt.expected {
				t.Errorf("IsSuperKey() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		expected  bool
	}{
		{"nil expiration never expires", nil, false},
		{"past expiration is expired", &past, true},
		{"future expiration not expired", &future, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{ExpiresAt: tt.expiresAt}
			result := key.IsExpired()
			if result != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAPIKey_CanAccess(t *testing.T) {
	tests := []struct {
		name      string
		scopes    []string
		agentTags []string
		expected  bool
	}{
		{
			name:      "super key with empty scopes",
			scopes:    []string{},
			agentTags: []string{"anything"},
			expected:  true,
		},
		{
			name:      "super key with wildcard",
			scopes:    []string{"*"},
			agentTags: []string{"anything"},
			expected:  true,
		},
		{
			name:      "exact match single scope",
			scopes:    []string{"finance"},
			agentTags: []string{"finance", "internal"},
			expected:  true,
		},
		{
			name:      "no match",
			scopes:    []string{"finance"},
			agentTags: []string{"hr", "internal"},
			expected:  false,
		},
		{
			name:      "pattern match prefix",
			scopes:    []string{"finance*"},
			agentTags: []string{"finance-internal"},
			expected:  true,
		},
		{
			name:      "pattern match suffix",
			scopes:    []string{"*-internal"},
			agentTags: []string{"finance-internal"},
			expected:  true,
		},
		{
			name:      "multiple scopes one match",
			scopes:    []string{"hr", "finance"},
			agentTags: []string{"finance"},
			expected:  true,
		},
		{
			name:      "multiple scopes no match",
			scopes:    []string{"hr", "engineering"},
			agentTags: []string{"finance", "admin"},
			expected:  false,
		},
		{
			name:      "empty agent tags",
			scopes:    []string{"finance"},
			agentTags: []string{},
			expected:  false,
		},
		{
			name:      "super key with empty agent tags",
			scopes:    []string{},
			agentTags: []string{},
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Scopes: tt.scopes}
			result := key.CanAccess(tt.agentTags)
			if result != tt.expected {
				t.Errorf("CanAccess(%v) = %v, want %v", tt.agentTags, result, tt.expected)
			}
		})
	}
}

func TestAPIKey_ExpandScopes(t *testing.T) {
	groups := map[string]ScopeGroup{
		"payment-workflow": {
			Name: "payment-workflow",
			Tags: []string{"finance", "audit", "notification"},
		},
		"reporting": {
			Name: "reporting",
			Tags: []string{"analytics", "shared"},
		},
	}

	tests := []struct {
		name           string
		scopes         []string
		expectedScopes []string
	}{
		{
			name:           "no groups",
			scopes:         []string{"finance", "hr"},
			expectedScopes: []string{"finance", "hr"},
		},
		{
			name:           "single group",
			scopes:         []string{"@payment-workflow"},
			expectedScopes: []string{"finance", "audit", "notification"},
		},
		{
			name:           "group and individual",
			scopes:         []string{"@payment-workflow", "custom"},
			expectedScopes: []string{"finance", "audit", "notification", "custom"},
		},
		{
			name:           "multiple groups",
			scopes:         []string{"@payment-workflow", "@reporting"},
			expectedScopes: []string{"finance", "audit", "notification", "analytics", "shared"},
		},
		{
			name:           "unknown group ignored",
			scopes:         []string{"@unknown", "finance"},
			expectedScopes: []string{"finance"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Scopes: tt.scopes}
			key.ExpandScopes(groups)

			if len(key.ExpandedScopes) != len(tt.expectedScopes) {
				t.Errorf("ExpandScopes() = %v, want %v", key.ExpandedScopes, tt.expectedScopes)
				return
			}

			for i, expected := range tt.expectedScopes {
				if key.ExpandedScopes[i] != expected {
					t.Errorf("ExpandScopes()[%d] = %v, want %v", i, key.ExpandedScopes[i], expected)
				}
			}
		})
	}
}

func TestAPIKey_GetEffectiveScopes(t *testing.T) {
	tests := []struct {
		name           string
		scopes         []string
		expandedScopes []string
		expected       []string
	}{
		{
			name:           "returns expanded if available",
			scopes:         []string{"@group"},
			expandedScopes: []string{"tag1", "tag2"},
			expected:       []string{"tag1", "tag2"},
		},
		{
			name:           "returns raw scopes if no expansion",
			scopes:         []string{"finance", "hr"},
			expandedScopes: nil,
			expected:       []string{"finance", "hr"},
		},
		{
			name:           "returns raw scopes if expansion empty",
			scopes:         []string{"finance"},
			expandedScopes: []string{},
			expected:       []string{"finance"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{
				Scopes:         tt.scopes,
				ExpandedScopes: tt.expandedScopes,
			}
			result := key.GetEffectiveScopes()

			if len(result) != len(tt.expected) {
				t.Errorf("GetEffectiveScopes() = %v, want %v", result, tt.expected)
				return
			}

			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("GetEffectiveScopes()[%d] = %v, want %v", i, result[i], expected)
				}
			}
		})
	}
}

func TestAPIKey_ToResponse(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	lastUsedAt := now.Add(-time.Hour)

	key := &APIKey{
		ID:          "key_123",
		Name:        "test-key",
		KeyHash:     "secret-hash-should-not-appear",
		Scopes:      []string{"finance", "hr"},
		Description: "Test key",
		Enabled:     true,
		CreatedAt:   now,
		ExpiresAt:   &expiresAt,
		LastUsedAt:  &lastUsedAt,
	}

	response := key.ToResponse()

	if response.ID != key.ID {
		t.Errorf("ToResponse().ID = %v, want %v", response.ID, key.ID)
	}
	if response.Name != key.Name {
		t.Errorf("ToResponse().Name = %v, want %v", response.Name, key.Name)
	}
	if len(response.Scopes) != len(key.Scopes) {
		t.Errorf("ToResponse().Scopes = %v, want %v", response.Scopes, key.Scopes)
	}
	if response.Description != key.Description {
		t.Errorf("ToResponse().Description = %v, want %v", response.Description, key.Description)
	}
	if response.Enabled != key.Enabled {
		t.Errorf("ToResponse().Enabled = %v, want %v", response.Enabled, key.Enabled)
	}
}
