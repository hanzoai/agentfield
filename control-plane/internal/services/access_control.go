package services

import (
	"context"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// AccessControlService handles access control decisions for the policy engine.
type AccessControlService struct {
	auditEnabled bool
	auditStorage storage.AccessAuditStorage
	scopeGroups  map[string]types.ScopeGroup
}

// NewAccessControlService creates a new access control service.
func NewAccessControlService(
	auditEnabled bool,
	auditStorage storage.AccessAuditStorage,
	scopeGroups map[string]types.ScopeGroup,
) *AccessControlService {
	return &AccessControlService{
		auditEnabled: auditEnabled,
		auditStorage: auditStorage,
		scopeGroups:  scopeGroups,
	}
}

// CheckAccess verifies if the given scopes can access an agent with the given tags.
// Returns an AccessDecision with the result and reasoning.
func (s *AccessControlService) CheckAccess(
	ctx context.Context,
	keyID, keyName string,
	keyScopes []string,
	targetAgent, targetReasoner string,
	agentTags []string,
) types.AccessDecision {
	decision := types.AccessDecision{
		KeyScopes: keyScopes,
		AgentTags: agentTags,
	}

	// Super key check - empty scopes or ["*"] means full access
	if isSuperKeyScopes(keyScopes) {
		decision.Allowed = true
		decision.MatchedOn = "*"
		return decision
	}

	// Expand any @group references in scopes
	effectiveScopes := s.expandScopes(keyScopes)

	// Check for any matching scope/tag pair
	for _, scope := range effectiveScopes {
		for _, tag := range agentTags {
			if types.MatchesTagPattern(scope, tag) {
				decision.Allowed = true
				decision.MatchedOn = scope + " -> " + tag
				s.logDecision(ctx, keyID, keyName, targetAgent, targetReasoner, decision)
				return decision
			}
		}
	}

	// No match found
	decision.Allowed = false
	decision.DenyReason = "no matching tags"
	s.logDecision(ctx, keyID, keyName, targetAgent, targetReasoner, decision)
	return decision
}

// FilterAgentsByAccess filters a list of agents to only those accessible by the given scopes.
func (s *AccessControlService) FilterAgentsByAccess(
	agents []*types.AgentNode,
	keyScopes []string,
) []*types.AgentNode {
	// Super key sees everything
	if isSuperKeyScopes(keyScopes) {
		return agents
	}

	// Expand any @group references
	effectiveScopes := s.expandScopes(keyScopes)

	permitted := make([]*types.AgentNode, 0, len(agents))
	for _, agent := range agents {
		agentTags := GetAgentTags(agent)
		if canAccessWithScopes(effectiveScopes, agentTags) {
			permitted = append(permitted, agent)
		}
	}
	return permitted
}

// GetAgentTags extracts all unique tags from an agent's Tags field,
// plus all tags from its reasoners and skills.
func GetAgentTags(agent *types.AgentNode) []string {
	tagSet := make(map[string]struct{})

	// Agent-level tags
	for _, t := range agent.Tags {
		tagSet[t] = struct{}{}
	}

	// Reasoner tags
	for _, r := range agent.Reasoners {
		for _, t := range r.Tags {
			tagSet[t] = struct{}{}
		}
	}

	// Skill tags
	for _, s := range agent.Skills {
		for _, t := range s.Tags {
			tagSet[t] = struct{}{}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags
}

// isSuperKeyScopes returns true if the scopes represent a super key.
func isSuperKeyScopes(scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	if len(scopes) == 1 && scopes[0] == "*" {
		return true
	}
	return false
}

// canAccessWithScopes checks if scopes can access agent tags.
func canAccessWithScopes(scopes, agentTags []string) bool {
	if isSuperKeyScopes(scopes) {
		return true
	}

	for _, scope := range scopes {
		for _, tag := range agentTags {
			if types.MatchesTagPattern(scope, tag) {
				return true
			}
		}
	}
	return false
}

// expandScopes resolves @group references in scopes.
func (s *AccessControlService) expandScopes(scopes []string) []string {
	if s.scopeGroups == nil || len(s.scopeGroups) == 0 {
		return scopes
	}

	expanded := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if len(scope) > 1 && scope[0] == '@' {
			groupName := scope[1:]
			if group, ok := s.scopeGroups[groupName]; ok {
				expanded = append(expanded, group.Tags...)
			} else {
				// Keep the scope as-is if group not found
				expanded = append(expanded, scope)
			}
		} else {
			expanded = append(expanded, scope)
		}
	}
	return expanded
}

// logDecision logs an access decision if audit is enabled.
func (s *AccessControlService) logDecision(
	ctx context.Context,
	keyID, keyName, targetAgent, targetReasoner string,
	decision types.AccessDecision,
) {
	if !s.auditEnabled || s.auditStorage == nil {
		return
	}

	entry := types.AccessAuditEntry{
		Timestamp:      time.Now(),
		APIKeyID:       keyID,
		APIKeyName:     keyName,
		TargetAgent:    targetAgent,
		TargetReasoner: targetReasoner,
		AgentTags:      decision.AgentTags,
		KeyScopes:      decision.KeyScopes,
		Allowed:        decision.Allowed,
		DenyReason:     decision.DenyReason,
	}

	// Log async to not block request
	go func() {
		if err := s.auditStorage.LogAccessDecision(ctx, entry); err != nil {
			logger.Logger.Warn().Err(err).Msg("failed to log access decision")
		}
	}()
}
