package services

import (
	"strings"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// CanonicalAgentTags returns normalized plain tags for permission matching.
// Canonical tags are lowercased, trimmed, plain values (e.g. "admin").
func CanonicalAgentTags(agent *types.AgentNode) []string {
	if agent == nil {
		return nil
	}

	seen := make(map[string]struct{})
	tags := make([]string, 0)

	add := func(tag string) {
		normalized := normalizeTag(tag)
		if normalized == "" {
			return
		}
		if _, exists := seen[normalized]; exists {
			return
		}
		seen[normalized] = struct{}{}
		tags = append(tags, normalized)
	}

	if agent.Metadata.Deployment != nil && agent.Metadata.Deployment.Tags != nil {
		for key, value := range agent.Metadata.Deployment.Tags {
			// Canonical format uses plain values, but include keys for compatibility.
			add(value)
			add(key)
		}
	}

	for _, reasoner := range agent.Reasoners {
		for _, tag := range reasoner.Tags {
			add(tag)
		}
	}

	for _, skill := range agent.Skills {
		for _, tag := range skill.Tags {
			add(tag)
		}
	}

	if agent.DeploymentType != "" {
		add(agent.DeploymentType)
	}

	return tags
}

func normalizeTag(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}
