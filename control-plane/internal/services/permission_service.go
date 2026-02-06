package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/google/uuid"
)

// PermissionService handles permission requests, approvals, and VC issuance.
type PermissionService struct {
	storage       PermissionStorage
	didWebService *DIDWebService
	vcService     *VCService
	config        *PermissionConfig
	mu            sync.RWMutex
	rules         []*types.ProtectedAgentRule
}

// PermissionStorage defines the storage interface for permissions.
type PermissionStorage interface {
	// Permission approvals
	CreatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error
	GetPermissionApproval(ctx context.Context, callerDID, targetDID string) (*types.PermissionApproval, error)
	GetPermissionApprovalByID(ctx context.Context, id int64) (*types.PermissionApproval, error)
	UpdatePermissionApproval(ctx context.Context, approval *types.PermissionApproval) error
	ListPermissionApprovals(ctx context.Context, status types.PermissionStatus) ([]*types.PermissionApproval, error)
	ListAllPermissionApprovals(ctx context.Context) ([]*types.PermissionApproval, error)

	// Protected agent rules
	GetProtectedAgentRules(ctx context.Context) ([]*types.ProtectedAgentRule, error)
	CreateProtectedAgentRule(ctx context.Context, rule *types.ProtectedAgentRule) error
	DeleteProtectedAgentRule(ctx context.Context, id int64) error
}

// PermissionConfig holds configuration for the permission service.
type PermissionConfig struct {
	Enabled              bool
	DefaultDurationHours int
	AutoRequestOnDeny    bool
}

// NewPermissionService creates a new permission service instance.
func NewPermissionService(
	storage PermissionStorage,
	didWebService *DIDWebService,
	vcService *VCService,
	config *PermissionConfig,
) *PermissionService {
	return &PermissionService{
		storage:       storage,
		didWebService: didWebService,
		vcService:     vcService,
		config:        config,
		rules:         make([]*types.ProtectedAgentRule, 0),
	}
}

// Initialize loads protected agent rules from storage.
func (s *PermissionService) Initialize(ctx context.Context) error {
	rules, err := s.storage.GetProtectedAgentRules(ctx)
	if err != nil {
		return fmt.Errorf("failed to load protected agent rules: %w", err)
	}
	s.mu.Lock()
	s.rules = rules
	s.mu.Unlock()

	logger.Logger.Info().
		Int("rules_count", len(rules)).
		Msg("Loaded protected agent rules")

	return nil
}

// IsEnabled returns whether the permission system is enabled.
func (s *PermissionService) IsEnabled() bool {
	return s.config != nil && s.config.Enabled
}

// RequestPermission creates a new permission request for a caller to call a target.
func (s *PermissionService) RequestPermission(ctx context.Context, req *types.PermissionRequest) (*types.PermissionApproval, error) {
	// Check if a request already exists
	existing, err := s.storage.GetPermissionApproval(ctx, req.CallerDID, req.TargetDID)
	if err == nil && existing != nil {
		// If pending or approved, return existing record as-is
		if existing.Status == types.PermissionStatusPending || existing.Status == types.PermissionStatusApproved {
			return existing, nil
		}
		// If rejected or revoked, reset to pending so it can be re-evaluated
		existing.Status = types.PermissionStatusPending
		existing.Reason = &req.Reason
		existing.UpdatedAt = time.Now()
		existing.RejectedBy = nil
		existing.RejectedAt = nil
		existing.RevokedBy = nil
		existing.RevokedAt = nil
		if err := s.storage.UpdatePermissionApproval(ctx, existing); err != nil {
			return nil, fmt.Errorf("failed to re-request permission: %w", err)
		}
		logger.Logger.Info().
			Str("caller_did", req.CallerDID).
			Str("target_did", req.TargetDID).
			Msg("Re-requested previously rejected/revoked permission")
		return existing, nil
	}

	// Create new approval record
	approval := &types.PermissionApproval{
		CallerDID:     req.CallerDID,
		TargetDID:     req.TargetDID,
		CallerAgentID: req.CallerAgentID,
		TargetAgentID: req.TargetAgentID,
		Status:        types.PermissionStatusPending,
		Reason:        &req.Reason,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.storage.CreatePermissionApproval(ctx, approval); err != nil {
		return nil, fmt.Errorf("failed to create permission request: %w", err)
	}

	logger.Logger.Info().
		Str("caller_did", req.CallerDID).
		Str("target_did", req.TargetDID).
		Msg("Created permission request")

	return approval, nil
}

// CheckPermission checks if a caller has permission to call a target.
func (s *PermissionService) CheckPermission(ctx context.Context, callerDID, targetDID string, targetAgentID string, targetTags []string) (*types.PermissionCheck, error) {
	result := &types.PermissionCheck{
		RequiresPermission: false,
		HasValidApproval:   true,
	}

	// Check if permission system is enabled
	if !s.IsEnabled() {
		return result, nil
	}

	// Check if target requires permission
	if !s.IsAgentProtected(targetAgentID, targetTags) {
		return result, nil
	}

	result.RequiresPermission = true
	result.HasValidApproval = false

	// Check if approval exists
	approval, err := s.storage.GetPermissionApproval(ctx, callerDID, targetDID)
	if err != nil {
		if !isNotFoundError(err) {
			return nil, fmt.Errorf("failed to check permission approval: %w", err)
		}
		// No approval exists
		result.ApprovalStatus = ""
		return result, nil
	}

	result.ApprovalID = &approval.ID
	result.ApprovalStatus = approval.Status

	// Check if approval is valid
	if approval.IsValid() {
		result.HasValidApproval = true
		result.ExpiresAt = approval.ExpiresAt

		// Generate VC if needed (could be cached)
		// For now, we just return the approval status
	}

	return result, nil
}

// IsAgentProtected checks if an agent requires permission to call based on rules.
func (s *PermissionService) IsAgentProtected(agentID string, tags []string) bool {
	canonicalTags := make([]string, 0, len(tags))
	for _, tag := range tags {
		if normalized := normalizeTag(tag); normalized != "" {
			canonicalTags = append(canonicalTags, normalized)
		}
	}

	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		switch rule.PatternType {
		case types.PatternTypeAgentID:
			if matchesPattern(rule.Pattern, agentID) {
				return true
			}
		case types.PatternTypeTag:
			normalizedPattern := normalizeTag(rule.Pattern)
			legacyPattern := normalizeLegacyTagPattern(rule.Pattern)
			for _, tag := range canonicalTags {
				if tag == normalizedPattern || tag == legacyPattern {
					return true
				}
			}
		case types.PatternTypeTagPattern:
			normalizedPattern := normalizeTag(rule.Pattern)
			legacyPattern := normalizeLegacyTagPattern(rule.Pattern)
			for _, tag := range canonicalTags {
				if matchesPattern(normalizedPattern, tag) || (legacyPattern != normalizedPattern && matchesPattern(legacyPattern, tag)) {
					return true
				}
			}
		}
	}
	return false
}

// ApprovePermission approves a pending permission request.
func (s *PermissionService) ApprovePermission(ctx context.Context, id int64, approvedBy string, durationHours *int) (*types.PermissionApproval, error) {
	approval, err := s.storage.GetPermissionApprovalByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("permission request not found: %w", err)
	}

	if approval.Status != types.PermissionStatusPending {
		return nil, fmt.Errorf("permission is not in pending state: current status is %s", approval.Status)
	}

	now := time.Now()
	approval.Status = types.PermissionStatusApproved
	approval.ApprovedBy = &approvedBy
	approval.ApprovedAt = &now
	approval.UpdatedAt = now

	// Set expiration if duration is specified
	if durationHours != nil && *durationHours > 0 {
		expiresAt := now.Add(time.Duration(*durationHours) * time.Hour)
		approval.ExpiresAt = &expiresAt
	} else if s.config.DefaultDurationHours > 0 {
		expiresAt := now.Add(time.Duration(s.config.DefaultDurationHours) * time.Hour)
		approval.ExpiresAt = &expiresAt
	}

	if err := s.storage.UpdatePermissionApproval(ctx, approval); err != nil {
		return nil, fmt.Errorf("failed to approve permission: %w", err)
	}

	logger.Logger.Info().
		Int64("id", id).
		Str("approved_by", approvedBy).
		Str("caller_did", approval.CallerDID).
		Str("target_did", approval.TargetDID).
		Msg("Approved permission request")

	return approval, nil
}

// RejectPermission rejects a pending permission request.
func (s *PermissionService) RejectPermission(ctx context.Context, id int64, rejectedBy string, reason string) (*types.PermissionApproval, error) {
	approval, err := s.storage.GetPermissionApprovalByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("permission request not found: %w", err)
	}

	if approval.Status != types.PermissionStatusPending {
		return nil, fmt.Errorf("permission is not in pending state: current status is %s", approval.Status)
	}

	now := time.Now()
	approval.Status = types.PermissionStatusRejected
	approval.RejectedBy = &rejectedBy
	approval.RejectedAt = &now
	approval.UpdatedAt = now
	if reason != "" {
		approval.Reason = &reason
	}

	if err := s.storage.UpdatePermissionApproval(ctx, approval); err != nil {
		return nil, fmt.Errorf("failed to reject permission: %w", err)
	}

	logger.Logger.Info().
		Int64("id", id).
		Str("rejected_by", rejectedBy).
		Str("caller_did", approval.CallerDID).
		Str("target_did", approval.TargetDID).
		Msg("Rejected permission request")

	return approval, nil
}

// RevokePermission revokes an approved permission.
func (s *PermissionService) RevokePermission(ctx context.Context, id int64, revokedBy string, reason string) (*types.PermissionApproval, error) {
	approval, err := s.storage.GetPermissionApprovalByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("permission not found: %w", err)
	}

	if approval.Status != types.PermissionStatusApproved {
		return nil, fmt.Errorf("permission is not in approved state: current status is %s", approval.Status)
	}

	now := time.Now()
	approval.Status = types.PermissionStatusRevoked
	approval.RevokedBy = &revokedBy
	approval.RevokedAt = &now
	approval.UpdatedAt = now
	if reason != "" {
		approval.Reason = &reason
	}

	if err := s.storage.UpdatePermissionApproval(ctx, approval); err != nil {
		return nil, fmt.Errorf("failed to revoke permission: %w", err)
	}

	logger.Logger.Info().
		Int64("id", id).
		Str("revoked_by", revokedBy).
		Str("caller_did", approval.CallerDID).
		Str("target_did", approval.TargetDID).
		Msg("Revoked permission")

	return approval, nil
}

// ListPendingPermissions returns all pending permission requests.
func (s *PermissionService) ListPendingPermissions(ctx context.Context) ([]*types.PermissionApproval, error) {
	return s.storage.ListPermissionApprovals(ctx, types.PermissionStatusPending)
}

// ListApprovedPermissions returns all approved permissions.
func (s *PermissionService) ListApprovedPermissions(ctx context.Context) ([]*types.PermissionApproval, error) {
	return s.storage.ListPermissionApprovals(ctx, types.PermissionStatusApproved)
}

// ListAllPermissions returns all permissions regardless of status.
func (s *PermissionService) ListAllPermissions(ctx context.Context) ([]*types.PermissionApproval, error) {
	return s.storage.ListAllPermissionApprovals(ctx)
}

// GeneratePermissionVC generates a VerifiableCredential for an approved permission.
func (s *PermissionService) GeneratePermissionVC(ctx context.Context, approval *types.PermissionApproval) (*types.PermissionVCDocument, error) {
	if approval.Status != types.PermissionStatusApproved {
		return nil, fmt.Errorf("cannot generate VC for non-approved permission")
	}

	// Get the control plane's issuer DID
	issuerDID := s.didWebService.GenerateDIDWeb("agentfield")

	// Create the VC document
	vcID := fmt.Sprintf("urn:agentfield:permission-vc:%s", uuid.New().String())

	approvedAt := ""
	if approval.ApprovedAt != nil {
		approvedAt = approval.ApprovedAt.Format(time.RFC3339)
	}

	approvedBy := ""
	if approval.ApprovedBy != nil {
		approvedBy = *approval.ApprovedBy
	}

	vc := &types.PermissionVCDocument{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		Type: []string{
			"VerifiableCredential",
			"PermissionCredential",
		},
		ID:           vcID,
		Issuer:       issuerDID,
		IssuanceDate: time.Now().Format(time.RFC3339),
		CredentialSubject: types.PermissionVCCredentialSubject{
			Caller: types.PermissionVCAgent{
				DID:     approval.CallerDID,
				AgentID: approval.CallerAgentID,
			},
			Target: types.PermissionVCAgent{
				DID:     approval.TargetDID,
				AgentID: approval.TargetAgentID,
			},
			Permission: "call",
			ApprovedBy: approvedBy,
			ApprovedAt: approvedAt,
		},
	}

	// Add expiration if set
	if approval.ExpiresAt != nil {
		vc.ExpirationDate = approval.ExpiresAt.Format(time.RFC3339)
	}

	// Explicitly classify this as an unsigned, non-verifiable audit record
	// until cryptographic signing is implemented.
	vc.Proof = &types.VCProof{
		Type:         "UnsignedAuditRecord",
		Created:      time.Now().Format(time.RFC3339),
		ProofPurpose: "assertionMethod",
		ProofValue:   "",
	}

	return vc, nil
}

// AddProtectedAgentRule adds a new protected agent rule.
func (s *PermissionService) AddProtectedAgentRule(ctx context.Context, req *types.ProtectedAgentRuleRequest) (*types.ProtectedAgentRule, error) {
	rule := &types.ProtectedAgentRule{
		PatternType: req.PatternType,
		Pattern:     req.Pattern,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if req.Description != "" {
		rule.Description = &req.Description
	}

	if err := s.storage.CreateProtectedAgentRule(ctx, rule); err != nil {
		return nil, fmt.Errorf("failed to create protected agent rule: %w", err)
	}

	// Reload rules
	if err := s.Initialize(ctx); err != nil {
		logger.Logger.Warn().Err(err).Msg("Failed to reload rules after adding new rule")
	}

	return rule, nil
}

// RemoveProtectedAgentRule removes a protected agent rule.
func (s *PermissionService) RemoveProtectedAgentRule(ctx context.Context, id int64) error {
	if err := s.storage.DeleteProtectedAgentRule(ctx, id); err != nil {
		return fmt.Errorf("failed to delete protected agent rule: %w", err)
	}

	// Reload rules
	if err := s.Initialize(ctx); err != nil {
		logger.Logger.Warn().Err(err).Msg("Failed to reload rules after removing rule")
	}

	return nil
}

// ListProtectedAgentRules returns all protected agent rules.
func (s *PermissionService) ListProtectedAgentRules(ctx context.Context) ([]*types.ProtectedAgentRule, error) {
	return s.storage.GetProtectedAgentRules(ctx)
}

// GetPermissionByID retrieves a permission approval by its ID.
func (s *PermissionService) GetPermissionByID(ctx context.Context, id int64) (*types.PermissionApproval, error) {
	return s.storage.GetPermissionApprovalByID(ctx, id)
}

// matchesPattern checks if a value matches a pattern (supports wildcards).
func matchesPattern(pattern, value string) bool {
	// Exact match
	if pattern == value {
		return true
	}

	// Full wildcard
	if pattern == "*" {
		return true
	}

	// Prefix wildcard (e.g., "finance*")
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}

	// Suffix wildcard (e.g., "*-internal")
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(value, suffix)
	}

	return false
}

func normalizeLegacyTagPattern(pattern string) string {
	p := normalizeTag(pattern)
	if idx := strings.Index(p, ":"); idx >= 0 && idx+1 < len(p) {
		return p[idx+1:]
	}
	return p
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no rows")
}
