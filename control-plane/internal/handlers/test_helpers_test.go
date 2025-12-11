package handlers

import (
	"context"
	"fmt"
	"sync"

	"github.com/Agent-Field/agentfield/control-plane/internal/events"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

type testExecutionStorage struct {
	mu                        sync.Mutex
	agent                     *types.AgentNode
	workflowExecutions        map[string]*types.WorkflowExecution
	executionRecords          map[string]*types.Execution
	runs                      map[string]*types.WorkflowRun
	steps                     map[string]*types.WorkflowStep
	webhooks                  map[string]*types.ExecutionWebhook
	webhookTriggers           map[string]*types.WebhookTrigger
	webhookDeliveries         map[string]*types.WebhookDelivery
	eventBus                  *events.ExecutionEventBus
	workflowExecutionEventBus *events.EventBus[*types.WorkflowExecutionEvent]
	workflowRunEventBus       *events.EventBus[*types.WorkflowRunEvent]
	updateCh                  chan string
}

func newTestExecutionStorage(agent *types.AgentNode) *testExecutionStorage {
	return &testExecutionStorage{
		agent:                     agent,
		workflowExecutions:        make(map[string]*types.WorkflowExecution),
		executionRecords:          make(map[string]*types.Execution),
		runs:                      make(map[string]*types.WorkflowRun),
		steps:                     make(map[string]*types.WorkflowStep),
		webhooks:                  make(map[string]*types.ExecutionWebhook),
		webhookTriggers:           make(map[string]*types.WebhookTrigger),
		webhookDeliveries:         make(map[string]*types.WebhookDelivery),
		eventBus:                  events.NewExecutionEventBus(),
		workflowExecutionEventBus: events.NewEventBus[*types.WorkflowExecutionEvent](),
		workflowRunEventBus:       events.NewEventBus[*types.WorkflowRunEvent](),
		updateCh:                  make(chan string, 10),
	}
}

func (s *testExecutionStorage) GetAgent(ctx context.Context, id string) (*types.AgentNode, error) {
	if s.agent != nil && s.agent.ID == id {
		return s.agent, nil
	}
	return nil, nil
}

func (s *testExecutionStorage) StoreWorkflowExecution(ctx context.Context, execution *types.WorkflowExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if execution == nil {
		return fmt.Errorf("execution cannot be nil")
	}
	s.workflowExecutions[execution.ExecutionID] = execution
	select {
	case s.updateCh <- execution.ExecutionID:
	default:
	}
	return nil
}

func (s *testExecutionStorage) UpdateWorkflowExecution(ctx context.Context, executionID string, updateFunc func(*types.WorkflowExecution) (*types.WorkflowExecution, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.workflowExecutions[executionID]
	if !ok {
		return fmt.Errorf("execution %s not found", executionID)
	}

	if updateFunc == nil {
		return fmt.Errorf("updateFunc cannot be nil")
	}

	updated, err := updateFunc(existing)
	if err != nil {
		return err
	}
	if updated != nil {
		s.workflowExecutions[executionID] = updated
	}
	select {
	case s.updateCh <- executionID:
	default:
	}
	return nil
}

func (s *testExecutionStorage) GetWorkflowExecution(ctx context.Context, executionID string) (*types.WorkflowExecution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	execution, ok := s.workflowExecutions[executionID]
	if !ok {
		return nil, nil
	}
	return execution, nil
}

func (s *testExecutionStorage) StoreWorkflowRun(ctx context.Context, run *types.WorkflowRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run == nil {
		return fmt.Errorf("run cannot be nil")
	}
	s.runs[run.RunID] = run
	return nil
}

func (s *testExecutionStorage) GetWorkflowRun(ctx context.Context, runID string) (*types.WorkflowRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		return nil, nil
	}
	return run, nil
}

func (s *testExecutionStorage) UpdateWorkflowRun(ctx context.Context, runID string, updateFunc func(*types.WorkflowRun) (*types.WorkflowRun, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		return fmt.Errorf("run %s not found", runID)
	}
	updated, err := updateFunc(run)
	if err != nil {
		return err
	}
	if updated != nil {
		s.runs[runID] = updated
	}
	return nil
}

func (s *testExecutionStorage) QueryWorkflowRuns(ctx context.Context, filters types.WorkflowRunFilters) ([]*types.WorkflowRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []*types.WorkflowRun
	for _, run := range s.runs {
		if filters.RunID != nil && *filters.RunID != run.RunID {
			continue
		}
		results = append(results, run)
	}
	return results, nil
}

func (s *testExecutionStorage) CountWorkflowRuns(ctx context.Context, filters types.WorkflowRunFilters) (int, error) {
	runs, _ := s.QueryWorkflowRuns(ctx, filters)
	return len(runs), nil
}

func (s *testExecutionStorage) StoreWorkflowStep(ctx context.Context, step *types.WorkflowStep) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if step == nil {
		return fmt.Errorf("step cannot be nil")
	}
	s.steps[step.StepID] = step
	return nil
}

func (s *testExecutionStorage) StoreWorkflowRunAndStep(ctx context.Context, run *types.WorkflowRun, step *types.WorkflowStep) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run == nil {
		return fmt.Errorf("run cannot be nil")
	}
	if step == nil {
		return fmt.Errorf("step cannot be nil")
	}
	s.runs[run.RunID] = run
	s.steps[step.StepID] = step
	return nil
}

func (s *testExecutionStorage) GetWorkflowStep(ctx context.Context, stepID string) (*types.WorkflowStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	step, ok := s.steps[stepID]
	if !ok {
		return nil, nil
	}
	return step, nil
}

func (s *testExecutionStorage) GetExecutionEventBus() *events.ExecutionEventBus {
	return s.eventBus
}

func (s *testExecutionStorage) GetWorkflowExecutionEventBus() *events.EventBus[*types.WorkflowExecutionEvent] {
	return s.workflowExecutionEventBus
}

func (s *testExecutionStorage) GetWorkflowRunEventBus() *events.EventBus[*types.WorkflowRunEvent] {
	return s.workflowRunEventBus
}

func (s *testExecutionStorage) RegisterExecutionWebhook(ctx context.Context, webhook *types.ExecutionWebhook) error {
	if webhook == nil {
		return fmt.Errorf("webhook cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhooks[webhook.ExecutionID] = webhook
	return nil
}

// Webhook trigger storage (basic in-memory impl for handler tests)
func (s *testExecutionStorage) CreateWebhookTrigger(ctx context.Context, trigger *types.WebhookTrigger) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhookTriggers[trigger.ID] = trigger
	return nil
}

func (s *testExecutionStorage) GetWebhookTrigger(ctx context.Context, triggerID string) (*types.WebhookTrigger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.webhookTriggers[triggerID]; ok {
		return t, nil
	}
	return nil, nil
}

func (s *testExecutionStorage) ListWebhookTriggers(ctx context.Context, filters types.WebhookTriggerFilters) ([]*types.WebhookTrigger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*types.WebhookTrigger, 0, len(s.webhookTriggers))
	for _, t := range s.webhookTriggers {
		result = append(result, t)
	}
	return result, nil
}

func (s *testExecutionStorage) UpdateWebhookTrigger(ctx context.Context, triggerID string, update func(*types.WebhookTrigger) (*types.WebhookTrigger, error)) (*types.WebhookTrigger, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.webhookTriggers[triggerID]
	if !ok {
		return nil, nil
	}
	updated, err := update(current)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		updated = current
	}
	s.webhookTriggers[triggerID] = updated
	return updated, nil
}

func (s *testExecutionStorage) DeleteWebhookTrigger(ctx context.Context, triggerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.webhookTriggers, triggerID)
	for id, d := range s.webhookDeliveries {
		if d.TriggerID == triggerID {
			delete(s.webhookDeliveries, id)
		}
	}
	return nil
}

func (s *testExecutionStorage) StoreWebhookDelivery(ctx context.Context, delivery *types.WebhookDelivery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhookDeliveries[delivery.ID] = delivery
	return nil
}

func (s *testExecutionStorage) FindDeliveryByEventID(ctx context.Context, triggerID, eventID string) (*types.WebhookDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.webhookDeliveries {
		if d.TriggerID == triggerID && d.EventID == eventID {
			return d, nil
		}
	}
	return nil, nil
}

func (s *testExecutionStorage) ListWebhookDeliveries(ctx context.Context, filters types.WebhookDeliveryFilters) ([]*types.WebhookDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*types.WebhookDelivery, 0)
	for _, d := range s.webhookDeliveries {
		if d.TriggerID != filters.TriggerID {
			continue
		}
		if filters.Status != nil && *filters.Status != "" && d.Status != *filters.Status {
			continue
		}
		result = append(result, d)
	}
	return result, nil
}

func (s *testExecutionStorage) CreateExecutionRecord(ctx context.Context, execution *types.Execution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if execution == nil {
		return fmt.Errorf("execution cannot be nil")
	}
	copy := *execution
	s.executionRecords[execution.ExecutionID] = &copy
	select {
	case s.updateCh <- execution.ExecutionID:
	default:
	}
	return nil
}

func (s *testExecutionStorage) GetExecutionRecord(ctx context.Context, executionID string) (*types.Execution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	execution, ok := s.executionRecords[executionID]
	if !ok {
		return nil, nil
	}
	copy := *execution
	return &copy, nil
}

func (s *testExecutionStorage) UpdateExecutionRecord(ctx context.Context, executionID string, update func(*types.Execution) (*types.Execution, error)) (*types.Execution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.executionRecords[executionID]
	if !ok {
		return nil, fmt.Errorf("execution %s not found", executionID)
	}

	cloned := *current
	updated, err := update(&cloned)
	if err != nil {
		return nil, err
	}
	if updated != nil {
		cloned = *updated
	}
	s.executionRecords[executionID] = &cloned
	select {
	case s.updateCh <- executionID:
	default:
	}
	out := cloned
	return &out, nil
}

func (s *testExecutionStorage) QueryExecutionRecords(ctx context.Context, filter types.ExecutionFilter) ([]*types.Execution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]*types.Execution, 0, len(s.executionRecords))
	for _, exec := range s.executionRecords {
		if filter.ExecutionID != nil && *filter.ExecutionID != exec.ExecutionID {
			continue
		}
		if filter.RunID != nil && *filter.RunID != exec.RunID {
			continue
		}
		copy := *exec
		results = append(results, &copy)
	}
	return results, nil
}
