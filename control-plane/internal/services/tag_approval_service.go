package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/config"
	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/google/uuid"
)

// TagApprovalResult holds the outcome of evaluating proposed tags against approval rules.
type TagApprovalResult struct {
	AutoApproved    []string
	ManualReview    []string
	Forbidden       []string
	AllAutoApproved bool
}

// TagApprovalStorage defines storage operations needed by the tag approval service.
type TagApprovalStorage interface {
	GetAgent(ctx context.Context, id string) (*types.AgentNode, error)
	RegisterAgent(ctx context.Context, node *types.AgentNode) error
	ListAgentsByLifecycleStatus(ctx context.Context, status types.AgentLifecycleStatus) ([]*types.AgentNode, error)
	GetAgentDID(ctx context.Context, agentID string) (*types.AgentDIDInfo, error)
	StoreAgentTagVC(ctx context.Context, agentID, agentDID, vcID, vcDocument, signature string, issuedAt time.Time, expiresAt *time.Time) error
}

// TagApprovalVCService defines the VC signing operations needed by the tag approval service.
type TagApprovalVCService interface {
	GetDIDService() *DIDService
	SignAgentTagVC(vc *types.AgentTagVCDocument) (*types.VCProof, error)
}

// TagApprovalService evaluates proposed tags against approval rules and manages
// the tag approval workflow for agents.
type TagApprovalService struct {
	config    config.TagApprovalRulesConfig
	storage   TagApprovalStorage
	vcService TagApprovalVCService // optional, can be nil
	mu        sync.RWMutex
}

// NewTagApprovalService creates a new tag approval service.
func NewTagApprovalService(cfg config.TagApprovalRulesConfig, storage TagApprovalStorage) *TagApprovalService {
	defaultMode := cfg.DefaultMode
	if defaultMode == "" {
		defaultMode = "auto"
	}
	cfg.DefaultMode = defaultMode

	return &TagApprovalService{
		config:  cfg,
		storage: storage,
	}
}

// SetVCService sets the VC service for tag VC issuance (optional dependency).
// Must be called during initialization before any concurrent use.
func (s *TagApprovalService) SetVCService(vcService TagApprovalVCService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vcService = vcService
}

// IsEnabled returns true if any tag approval rules require non-auto behavior.
func (s *TagApprovalService) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.config.Rules) > 0 || s.config.DefaultMode != "auto"
}

// EvaluateTags evaluates a set of proposed tags against the configured approval rules.
func (s *TagApprovalService) EvaluateTags(proposedTags []string) TagApprovalResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := TagApprovalResult{}

	for _, tag := range proposedTags {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		if normalized == "" {
			continue
		}

		mode := s.getTagApprovalMode(normalized)
		switch mode {
		case "auto":
			result.AutoApproved = append(result.AutoApproved, normalized)
		case "manual":
			result.ManualReview = append(result.ManualReview, normalized)
		case "forbidden":
			result.Forbidden = append(result.Forbidden, normalized)
		default:
			// Unknown mode treated as manual for safety
			result.ManualReview = append(result.ManualReview, normalized)
		}
	}

	result.AllAutoApproved = len(result.ManualReview) == 0 && len(result.Forbidden) == 0
	return result
}

// getTagApprovalMode returns the approval mode for a specific tag.
func (s *TagApprovalService) getTagApprovalMode(tag string) string {
	for _, rule := range s.config.Rules {
		for _, ruleTag := range rule.Tags {
			normalized := strings.ToLower(strings.TrimSpace(ruleTag))
			if normalized == tag {
				return rule.Approval
			}
		}
	}
	return s.config.DefaultMode
}

// CollectAllProposedTags extracts all proposed tags from an agent's reasoners and skills.
func CollectAllProposedTags(agent *types.AgentNode) []string {
	seen := make(map[string]struct{})
	var tags []string

	add := func(tag string) {
		normalized := strings.ToLower(strings.TrimSpace(tag))
		if normalized == "" {
			return
		}
		if _, exists := seen[normalized]; exists {
			return
		}
		seen[normalized] = struct{}{}
		tags = append(tags, normalized)
	}

	for _, r := range agent.Reasoners {
		proposed := r.ProposedTags
		if len(proposed) == 0 {
			proposed = r.Tags
		}
		for _, t := range proposed {
			add(t)
		}
	}

	for _, sk := range agent.Skills {
		proposed := sk.ProposedTags
		if len(proposed) == 0 {
			proposed = sk.Tags
		}
		for _, t := range proposed {
			add(t)
		}
	}

	return tags
}

// ApproveAgentTags approves an agent's tags, setting approved_tags and transitioning
// the lifecycle status from pending_approval to starting.
func (s *TagApprovalService) ApproveAgentTags(ctx context.Context, agentID string, approvedTags []string, approvedBy string) error {
	agent, err := s.storage.GetAgent(ctx, agentID)
	if err != nil {
		return err
	}

	if agent.LifecycleStatus != types.AgentStatusPendingApproval {
		return fmt.Errorf("agent %s is not pending approval (current status: %s)", agentID, agent.LifecycleStatus)
	}

	agent.ApprovedTags = approvedTags
	agent.LifecycleStatus = types.AgentStatusStarting

	// Set approved tags on each reasoner and skill
	approvedSet := make(map[string]struct{})
	for _, t := range approvedTags {
		approvedSet[strings.ToLower(strings.TrimSpace(t))] = struct{}{}
	}

	for i := range agent.Reasoners {
		var approved []string
		proposed := agent.Reasoners[i].ProposedTags
		if len(proposed) == 0 {
			proposed = agent.Reasoners[i].Tags
		}
		for _, t := range proposed {
			if _, ok := approvedSet[strings.ToLower(strings.TrimSpace(t))]; ok {
				approved = append(approved, t)
			}
		}
		agent.Reasoners[i].ApprovedTags = approved
	}

	for i := range agent.Skills {
		var approved []string
		proposed := agent.Skills[i].ProposedTags
		if len(proposed) == 0 {
			proposed = agent.Skills[i].Tags
		}
		for _, t := range proposed {
			if _, ok := approvedSet[strings.ToLower(strings.TrimSpace(t))]; ok {
				approved = append(approved, t)
			}
		}
		agent.Skills[i].ApprovedTags = approved
	}

	if err := s.storage.RegisterAgent(ctx, agent); err != nil {
		return err
	}

	logger.Logger.Info().
		Str("agent_id", agentID).
		Strs("approved_tags", approvedTags).
		Str("approved_by", approvedBy).
		Msg("Agent tags approved")

	// Issue a signed Agent Tag VC (non-fatal on failure)
	s.issueTagVC(ctx, agentID, approvedTags, approvedBy)

	return nil
}

// ApproveAgentTagsPerSkill approves tags at per-skill/per-reasoner granularity.
func (s *TagApprovalService) ApproveAgentTagsPerSkill(ctx context.Context, agentID string, skillTags map[string][]string, reasonerTags map[string][]string, approvedBy string) error {
	agent, err := s.storage.GetAgent(ctx, agentID)
	if err != nil {
		return err
	}

	if agent.LifecycleStatus != types.AgentStatusPendingApproval {
		return fmt.Errorf("agent %s is not pending approval (current status: %s)", agentID, agent.LifecycleStatus)
	}

	for i := range agent.Reasoners {
		if tags, ok := reasonerTags[agent.Reasoners[i].ID]; ok {
			agent.Reasoners[i].ApprovedTags = tags
		}
	}

	for i := range agent.Skills {
		if tags, ok := skillTags[agent.Skills[i].ID]; ok {
			agent.Skills[i].ApprovedTags = tags
		}
	}

	// Collect all approved tags for the agent-level field
	seen := make(map[string]struct{})
	var allApproved []string
	for _, r := range agent.Reasoners {
		for _, t := range r.ApprovedTags {
			normalized := strings.ToLower(strings.TrimSpace(t))
			if _, exists := seen[normalized]; !exists {
				seen[normalized] = struct{}{}
				allApproved = append(allApproved, normalized)
			}
		}
	}
	for _, sk := range agent.Skills {
		for _, t := range sk.ApprovedTags {
			normalized := strings.ToLower(strings.TrimSpace(t))
			if _, exists := seen[normalized]; !exists {
				seen[normalized] = struct{}{}
				allApproved = append(allApproved, normalized)
			}
		}
	}

	agent.ApprovedTags = allApproved
	agent.LifecycleStatus = types.AgentStatusStarting

	if err := s.storage.RegisterAgent(ctx, agent); err != nil {
		return err
	}

	logger.Logger.Info().
		Str("agent_id", agentID).
		Str("approved_by", approvedBy).
		Msg("Agent tags approved (per-skill)")

	// Issue a signed Agent Tag VC (non-fatal on failure)
	s.issueTagVC(ctx, agentID, allApproved, approvedBy)

	return nil
}

// RejectAgentTags rejects an agent's proposed tags.
func (s *TagApprovalService) RejectAgentTags(ctx context.Context, agentID string, rejectedBy string, reason string) error {
	agent, err := s.storage.GetAgent(ctx, agentID)
	if err != nil {
		return err
	}

	if agent.LifecycleStatus != types.AgentStatusPendingApproval {
		return fmt.Errorf("agent %s is not pending approval (current status: %s)", agentID, agent.LifecycleStatus)
	}

	agent.LifecycleStatus = types.AgentStatusOffline
	agent.ApprovedTags = nil

	// Clear approved tags on all skills/reasoners
	for i := range agent.Reasoners {
		agent.Reasoners[i].ApprovedTags = nil
	}
	for i := range agent.Skills {
		agent.Skills[i].ApprovedTags = nil
	}

	if err := s.storage.RegisterAgent(ctx, agent); err != nil {
		return err
	}

	logger.Logger.Info().
		Str("agent_id", agentID).
		Str("rejected_by", rejectedBy).
		Str("reason", reason).
		Msg("Agent tags rejected")

	return nil
}

// ListPendingAgents returns all agents currently in pending_approval status.
func (s *TagApprovalService) ListPendingAgents(ctx context.Context) ([]*types.AgentNode, error) {
	return s.storage.ListAgentsByLifecycleStatus(ctx, types.AgentStatusPendingApproval)
}

// ProcessRegistrationTags evaluates tags at registration time and returns the result.
// The caller should use this to decide whether to set the agent to pending or auto-approve.
func (s *TagApprovalService) ProcessRegistrationTags(agent *types.AgentNode) TagApprovalResult {
	allProposed := CollectAllProposedTags(agent)
	agent.ProposedTags = allProposed

	result := s.EvaluateTags(allProposed)

	if result.AllAutoApproved {
		// Auto-approve: set approved tags immediately
		agent.ApprovedTags = result.AutoApproved
		for i := range agent.Reasoners {
			agent.Reasoners[i].ApprovedTags = agent.Reasoners[i].Tags
			if len(agent.Reasoners[i].ApprovedTags) == 0 {
				agent.Reasoners[i].ApprovedTags = agent.Reasoners[i].ProposedTags
			}
		}
		for i := range agent.Skills {
			agent.Skills[i].ApprovedTags = agent.Skills[i].Tags
			if len(agent.Skills[i].ApprovedTags) == 0 {
				agent.Skills[i].ApprovedTags = agent.Skills[i].ProposedTags
			}
		}
	} else {
		// Needs approval: only auto-approved tags are set
		agent.ApprovedTags = result.AutoApproved
		agent.LifecycleStatus = types.AgentStatusPendingApproval
	}

	return result
}

// issueTagVC creates and stores a signed Agent Tag VC for an agent.
// This is non-fatal — if VC issuance fails, the tag approval still succeeds.
func (s *TagApprovalService) issueTagVC(ctx context.Context, agentID string, approvedTags []string, approvedBy string) {
	s.mu.RLock()
	vcSvc := s.vcService
	s.mu.RUnlock()
	if vcSvc == nil {
		return
	}

	// Get agent's DID
	agentDIDInfo, err := s.storage.GetAgentDID(ctx, agentID)
	if err != nil {
		logger.Logger.Warn().Err(err).Str("agent_id", agentID).Msg("Cannot issue tag VC: agent DID not found")
		return
	}

	// Get control plane issuer DID
	var issuerDID string
	didService := vcSvc.GetDIDService()
	if didService != nil {
		if rootDID, err := didService.GetControlPlaneIssuerDID(); err == nil {
			issuerDID = rootDID
		}
	}
	if issuerDID == "" {
		logger.Logger.Warn().Str("agent_id", agentID).Msg("Cannot issue tag VC: no issuer DID available")
		return
	}

	// Build the VC document
	now := time.Now()
	vcID := fmt.Sprintf("urn:agentfield:agent-tag-vc:%s", uuid.New().String())

	vc := &types.AgentTagVCDocument{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		Type: []string{
			"VerifiableCredential",
			"AgentTagCredential",
		},
		ID:           vcID,
		Issuer:       issuerDID,
		IssuanceDate: now.Format(time.RFC3339),
		CredentialSubject: types.AgentTagVCCredentialSubject{
			ID:      agentDIDInfo.DID,
			AgentID: agentID,
			Permissions: types.AgentTagVCPermissions{
				Tags:           approvedTags,
				AllowedCallees: []string{"*"},
			},
			ApprovedBy: approvedBy,
			ApprovedAt: now.Format(time.RFC3339),
		},
	}

	// Sign the VC
	proof, err := vcSvc.SignAgentTagVC(vc)
	if err != nil {
		logger.Logger.Warn().Err(err).Str("agent_id", agentID).Msg("Failed to sign agent tag VC")
		return
	}
	vc.Proof = proof

	// Serialize the VC document
	vcDocJSON, err := json.Marshal(vc)
	if err != nil {
		logger.Logger.Warn().Err(err).Str("agent_id", agentID).Msg("Failed to marshal agent tag VC")
		return
	}

	// Extract signature value for storage
	signature := ""
	if proof != nil {
		signature = proof.ProofValue
	}

	// Store the VC
	if err := s.storage.StoreAgentTagVC(ctx, agentID, agentDIDInfo.DID, vcID, string(vcDocJSON), signature, now, nil); err != nil {
		logger.Logger.Warn().Err(err).Str("agent_id", agentID).Msg("Failed to store agent tag VC")
		return
	}

	proofType := "none"
	if proof != nil {
		proofType = proof.Type
	}
	logger.Logger.Info().
		Str("agent_id", agentID).
		Str("vc_id", vcID).
		Str("proof_type", proofType).
		Msg("Agent tag VC issued")
}

