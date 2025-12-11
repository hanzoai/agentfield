package storage

import (
	"context"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// WebhookStore exposes storage operations for inbound webhook triggers and deliveries.
type WebhookStore interface {
	CreateWebhookTrigger(ctx context.Context, trigger *types.WebhookTrigger) error
	GetWebhookTrigger(ctx context.Context, triggerID string) (*types.WebhookTrigger, error)
	ListWebhookTriggers(ctx context.Context, filters types.WebhookTriggerFilters) ([]*types.WebhookTrigger, error)
	UpdateWebhookTrigger(ctx context.Context, triggerID string, update func(*types.WebhookTrigger) (*types.WebhookTrigger, error)) (*types.WebhookTrigger, error)
	DeleteWebhookTrigger(ctx context.Context, triggerID string) error

	StoreWebhookDelivery(ctx context.Context, delivery *types.WebhookDelivery) error
	DeleteWebhookDelivery(ctx context.Context, deliveryID string) error
	FindDeliveryByEventID(ctx context.Context, triggerID, eventID string) (*types.WebhookDelivery, error)
	ListWebhookDeliveries(ctx context.Context, filters types.WebhookDeliveryFilters) ([]*types.WebhookDelivery, error)
}

var _ WebhookStore = (*LocalStorage)(nil)
