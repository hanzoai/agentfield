package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// CreateExecutionRecord inserts a new execution row using the simplified schema.
func (ls *LocalStorage) CreateExecutionRecord(ctx context.Context, exec *types.Execution) error {
	if exec == nil {
		return fmt.Errorf("nil execution payload")
	}

	db := ls.requireSQLDB()

	now := time.Now().UTC()
	if exec.StartedAt.IsZero() {
		exec.StartedAt = now
	}
	exec.CreatedAt = now
	exec.UpdatedAt = now

	insert := `
		INSERT INTO executions (
			execution_id, run_id, parent_execution_id,
			agent_node_id, reasoner_id, node_id,
			status, input_payload, result_payload, error_message,
			input_uri, result_uri,
			session_id, actor_id,
			started_at, completed_at, duration_ms,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.ExecContext(
		ctx,
		insert,
		exec.ExecutionID,
		exec.RunID,
		exec.ParentExecutionID,
		exec.AgentNodeID,
		exec.ReasonerID,
		exec.NodeID,
		exec.Status,
		bytesOrNil(exec.InputPayload),
		bytesOrNil(exec.ResultPayload),
		exec.ErrorMessage,
		exec.InputURI,
		exec.ResultURI,
		exec.SessionID,
		exec.ActorID,
		exec.StartedAt,
		exec.CompletedAt,
		exec.DurationMS,
		exec.CreatedAt,
		exec.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert execution: %w", err)
	}

	return nil
}

// GetExecutionRecord fetches a single execution row by execution_id.
func (ls *LocalStorage) GetExecutionRecord(ctx context.Context, executionID string) (*types.Execution, error) {
	query := `
		SELECT execution_id, run_id, parent_execution_id,
		       agent_node_id, reasoner_id, node_id,
		       status, input_payload, result_payload, error_message,
		       input_uri, result_uri,
		       session_id, actor_id,
		       started_at, completed_at, duration_ms,
		       created_at, updated_at
		FROM executions
	WHERE execution_id = ?`

	db := ls.requireSQLDB()
	row := db.QueryRowContext(ctx, query, executionID)
	exec, err := scanExecution(row)
	if err != nil || exec == nil {
		return exec, err
	}

	ls.enrichExecutionWebhook(ctx, exec, true)
	return exec, nil
}

// UpdateExecutionRecord applies an update callback atomically. The callback mutates a
// types.Execution copy and the result gets persisted.
func (ls *LocalStorage) UpdateExecutionRecord(ctx context.Context, executionID string, updater func(*types.Execution) (*types.Execution, error)) (*types.Execution, error) {
	if updater == nil {
		return nil, fmt.Errorf("nil updater")
	}

	db := ls.requireSQLDB()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer rollbackTx(tx, "UpdateExecutionRecord:"+executionID)

	row := tx.QueryRowContext(ctx, `
		SELECT execution_id, run_id, parent_execution_id,
		       agent_node_id, reasoner_id, node_id,
		       status, input_payload, result_payload, error_message,
		       input_uri, result_uri,
		       session_id, actor_id,
		       started_at, completed_at, duration_ms,
		       created_at, updated_at
		FROM executions
		WHERE execution_id = ?`, executionID)

	current, err := scanExecution(row)
	if err != nil {
		return nil, err
	}

	updated, err := updater(current)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit execution update: %w", err)
		}
		ls.enrichExecutionWebhook(ctx, current, true)
		return current, nil
	}
	updated.UpdatedAt = time.Now().UTC()

	update := `
		UPDATE executions SET
			run_id = ?,
			parent_execution_id = ?,
			agent_node_id = ?,
			reasoner_id = ?,
			node_id = ?,
			status = ?,
			input_payload = ?,
			result_payload = ?,
			error_message = ?,
			input_uri = ?,
			result_uri = ?,
			session_id = ?,
			actor_id = ?,
			started_at = ?,
			completed_at = ?,
			duration_ms = ?,
			updated_at = ?
		WHERE execution_id = ?`

	_, err = tx.ExecContext(
		ctx,
		update,
		updated.RunID,
		updated.ParentExecutionID,
		updated.AgentNodeID,
		updated.ReasonerID,
		updated.NodeID,
		updated.Status,
		bytesOrNil(updated.InputPayload),
		bytesOrNil(updated.ResultPayload),
		updated.ErrorMessage,
		updated.InputURI,
		updated.ResultURI,
		updated.SessionID,
		updated.ActorID,
		updated.StartedAt,
		updated.CompletedAt,
		updated.DurationMS,
		updated.UpdatedAt,
		updated.ExecutionID,
	)
	if err != nil {
		return nil, fmt.Errorf("update execution: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit execution update: %w", err)
	}

	ls.enrichExecutionWebhook(ctx, updated, true)
	return updated, nil
}

// QueryExecutionRecords runs a filtered query returning all matching executions.
func (ls *LocalStorage) QueryExecutionRecords(ctx context.Context, filter types.ExecutionFilter) ([]*types.Execution, error) {
	var (
		where []string
		args  []interface{}
	)

	if filter.ExecutionID != nil {
		where = append(where, "execution_id = ?")
		args = append(args, *filter.ExecutionID)
	}
	if filter.RunID != nil {
		where = append(where, "run_id = ?")
		args = append(args, *filter.RunID)
	}
	if filter.ParentExecutionID != nil {
		where = append(where, "parent_execution_id = ?")
		args = append(args, *filter.ParentExecutionID)
	}
	if filter.AgentNodeID != nil {
		where = append(where, "agent_node_id = ?")
		args = append(args, *filter.AgentNodeID)
	}
	if filter.ReasonerID != nil {
		where = append(where, "reasoner_id = ?")
		args = append(args, *filter.ReasonerID)
	}
	if filter.Status != nil {
		where = append(where, "status = ?")
		args = append(args, *filter.Status)
	}
	if filter.SessionID != nil {
		where = append(where, "session_id = ?")
		args = append(args, *filter.SessionID)
	}
	if filter.ActorID != nil {
		where = append(where, "actor_id = ?")
		args = append(args, *filter.ActorID)
	}
	if filter.StartTime != nil {
		where = append(where, "started_at >= ?")
		args = append(args, filter.StartTime.UTC())
	}
	if filter.EndTime != nil {
		where = append(where, "started_at <= ?")
		args = append(args, filter.EndTime.UTC())
	}

	queryBuilder := strings.Builder{}
	queryBuilder.WriteString(`
		SELECT execution_id, run_id, parent_execution_id,
		       agent_node_id, reasoner_id, node_id,
		       status, input_payload, result_payload, error_message,
		       input_uri, result_uri,
		       session_id, actor_id,
		       started_at, completed_at, duration_ms,
		       created_at, updated_at
		FROM executions`)

	if len(where) > 0 {
		queryBuilder.WriteString(" WHERE ")
		queryBuilder.WriteString(strings.Join(where, " AND "))
	}
	orderColumn := "started_at"
	switch filter.SortBy {
	case "status":
		orderColumn = "status"
	case "duration_ms":
		orderColumn = "duration_ms"
	case "agent_node_id":
		orderColumn = "agent_node_id"
	case "reasoner_id":
		orderColumn = "reasoner_id"
	case "execution_id":
		orderColumn = "execution_id"
	case "run_id":
		orderColumn = "run_id"
	case "created_at":
		orderColumn = "created_at"
	case "updated_at":
		orderColumn = "updated_at"
	}
	orderDirection := "DESC"
	if !filter.SortDescending {
		orderDirection = "ASC"
	}
	queryBuilder.WriteString(" ORDER BY " + orderColumn + " " + orderDirection)

	if filter.Limit > 0 {
		queryBuilder.WriteString(fmt.Sprintf(" LIMIT %d", filter.Limit))
	}
	if filter.Offset > 0 {
		queryBuilder.WriteString(fmt.Sprintf(" OFFSET %d", filter.Offset))
	}

	db := ls.requireSQLDB()
	rows, err := db.QueryContext(ctx, queryBuilder.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query executions: %w", err)
	}
	defer rows.Close()

	var executions []*types.Execution
	for rows.Next() {
		exec, err := scanExecution(rows)
		if err != nil {
			return nil, err
		}
		executions = append(executions, exec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate executions: %w", err)
	}

	ls.populateWebhookRegistration(ctx, executions)

	return executions, nil
}

// QueryRunSummaries returns aggregated statistics for workflow runs without fetching all execution records.
// This is highly efficient for workflows with millions of nodes as it uses database-level GROUP BY and COUNT.
func (ls *LocalStorage) QueryRunSummaries(ctx context.Context, filter types.ExecutionFilter) ([]*RunSummaryAggregation, error) {
	var (
		where []string
		args  []interface{}
	)

	// Build WHERE clause from filter (excluding execution-specific filters)
	if filter.RunID != nil {
		where = append(where, "run_id = ?")
		args = append(args, *filter.RunID)
	}
	if filter.Status != nil {
		where = append(where, "status = ?")
		args = append(args, *filter.Status)
	}
	if filter.SessionID != nil {
		where = append(where, "session_id = ?")
		args = append(args, *filter.SessionID)
	}
	if filter.ActorID != nil {
		where = append(where, "actor_id = ?")
		args = append(args, *filter.ActorID)
	}
	if filter.StartTime != nil {
		where = append(where, "started_at >= ?")
		args = append(args, filter.StartTime.UTC())
	}
	if filter.EndTime != nil {
		where = append(where, "started_at <= ?")
		args = append(args, filter.EndTime.UTC())
	}

	// Step 1: Get distinct run_ids with their earliest timestamps for sorting
	distinctQuery := strings.Builder{}
	distinctQuery.WriteString(`
		SELECT run_id, MIN(started_at) as earliest_started
		FROM executions`)

	if len(where) > 0 {
		distinctQuery.WriteString(" WHERE ")
		distinctQuery.WriteString(strings.Join(where, " AND "))
	}

	distinctQuery.WriteString(" GROUP BY run_id")
	distinctQuery.WriteString(" ORDER BY earliest_started DESC")

	if filter.Limit > 0 {
		distinctQuery.WriteString(fmt.Sprintf(" LIMIT %d", filter.Limit))
	}
	if filter.Offset > 0 {
		distinctQuery.WriteString(fmt.Sprintf(" OFFSET %d", filter.Offset))
	}

	db := ls.requireSQLDB()

	// Log the query for debugging
	logger.Logger.Debug().
		Str("query", distinctQuery.String()).
		Interface("args", args).
		Msg("Executing run summary query")

	rows, err := db.QueryContext(ctx, distinctQuery.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query distinct run_ids: %w", err)
	}
	defer rows.Close()

	var runIDs []string
	for rows.Next() {
		var runID string
		var earliestStarted string // SQLite stores timestamps as strings
		if err := rows.Scan(&runID, &earliestStarted); err != nil {
			return nil, fmt.Errorf("scan run_id: %w", err)
		}
		runIDs = append(runIDs, runID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate run_ids: %w", err)
	}

	logger.Logger.Debug().Int("count", len(runIDs)).Strs("run_ids", runIDs).Msg("Found run IDs")

	if len(runIDs) == 0 {
		logger.Logger.Info().Msg("No run IDs found matching filter")
		return []*RunSummaryAggregation{}, nil
	}

	// Step 2: Get aggregated statistics for each run
	summaries := make([]*RunSummaryAggregation, 0, len(runIDs))

	for _, runID := range runIDs {
		summary, err := ls.getRunAggregation(ctx, runID)
		if err != nil {
			logger.Logger.Warn().Str("run_id", runID).Err(err).Msg("failed to get run aggregation, skipping")
			continue
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// getRunAggregation computes aggregated statistics for a single run using efficient SQL queries
func (ls *LocalStorage) getRunAggregation(ctx context.Context, runID string) (*RunSummaryAggregation, error) {
	db := ls.requireSQLDB()

	summary := &RunSummaryAggregation{
		RunID:        runID,
		StatusCounts: make(map[string]int),
	}

	// Query 1: Get overall statistics and root execution info
	statsQuery := `
		SELECT
			COUNT(*) as total_executions,
			MIN(started_at) as earliest_started,
			MAX(started_at) as latest_started
		FROM executions
		WHERE run_id = ?`

	var earliestVal interface{}
	var latestVal interface{}
	err := db.QueryRowContext(ctx, statsQuery, runID).Scan(
		&summary.TotalExecutions,
		&earliestVal,
		&latestVal,
	)
	if err != nil {
		return nil, fmt.Errorf("query run stats for %s: %w", runID, err)
	}

	if err := assignTimeValue(&summary.EarliestStarted, earliestVal); err != nil {
		logger.Logger.Warn().
			Str("run_id", runID).
			Interface("value", earliestVal).
			Err(err).
			Msg("failed to parse earliest_started for run summary; using current time as fallback")
		summary.EarliestStarted = time.Now().UTC()
	}

	if err := assignTimeValue(&summary.LatestStarted, latestVal); err != nil {
		logger.Logger.Warn().
			Str("run_id", runID).
			Interface("value", latestVal).
			Err(err).
			Msg("failed to parse latest_started for run summary; using current time as fallback")
		summary.LatestStarted = time.Now().UTC()
	}

	// Query 2: Get status counts
	statusQuery := `
		SELECT status, COUNT(*) as count
		FROM executions
		WHERE run_id = ?
		GROUP BY status`

	statusRows, err := db.QueryContext(ctx, statusQuery, runID)
	if err != nil {
		return nil, fmt.Errorf("query status counts: %w", err)
	}
	defer statusRows.Close()

	activeCount := 0
	for statusRows.Next() {
		var status string
		var count int
		if err := statusRows.Scan(&status, &count); err != nil {
			return nil, fmt.Errorf("scan status count: %w", err)
		}
		normalized := types.NormalizeExecutionStatus(status)
		summary.StatusCounts[normalized] = count

		// Count active executions
		if normalized == string(types.ExecutionStatusRunning) ||
			normalized == string(types.ExecutionStatusPending) ||
			normalized == string(types.ExecutionStatusQueued) {
			activeCount += count
		}
	}
	summary.ActiveExecutions = activeCount

	// Query 3: Get root execution info (execution with no parent)
	rootQuery := `
		SELECT execution_id, agent_node_id, reasoner_id, session_id, actor_id
		FROM executions
		WHERE run_id = ? AND (parent_execution_id IS NULL OR parent_execution_id = '')
		ORDER BY started_at ASC
		LIMIT 1`

	var rootExecID, rootAgentNodeID, rootReasonerID sql.NullString
	var sessionID, actorID sql.NullString
	err = db.QueryRowContext(ctx, rootQuery, runID).Scan(
		&rootExecID,
		&rootAgentNodeID,
		&rootReasonerID,
		&sessionID,
		&actorID,
	)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("query root execution: %w", err)
	}

	if rootExecID.Valid {
		summary.RootExecutionID = &rootExecID.String
	}
	if rootAgentNodeID.Valid {
		summary.RootAgentNodeID = &rootAgentNodeID.String
	}
	if rootReasonerID.Valid {
		summary.RootReasonerID = &rootReasonerID.String
	}
	if sessionID.Valid && sessionID.String != "" {
		summary.SessionID = &sessionID.String
	}
	if actorID.Valid && actorID.String != "" {
		summary.ActorID = &actorID.String
	}

	// Query 4: Calculate max depth (this is more expensive but still better than fetching all records)
	// For workflows with > 1k nodes, skip depth calculation to avoid memory issues
	const maxNodesForDepthCalc = 1000

	if summary.TotalExecutions > maxNodesForDepthCalc {
		// For very large workflows, estimate depth or skip it
		// TODO: Consider storing depth in the database for efficiency
		summary.MaxDepth = -1 // Indicates depth was not calculated
		logger.Logger.Debug().
			Str("run_id", runID).
			Int("total_executions", summary.TotalExecutions).
			Msg("skipping depth calculation for large workflow")
	} else {
		// We'll use a recursive approach or compute it from parent relationships
		// For simplicity, we'll fetch just parent_execution_id and execution_id to build depth map
		depthQuery := `
			SELECT execution_id, parent_execution_id
			FROM executions
			WHERE run_id = ?`

		depthRows, err := db.QueryContext(ctx, depthQuery, runID)
		if err != nil {
			return nil, fmt.Errorf("query depth info: %w", err)
		}
		defer depthRows.Close()

		var execInfos []execDepthInfo

		for depthRows.Next() {
			var execID string
			var parentID sql.NullString
			if err := depthRows.Scan(&execID, &parentID); err != nil {
				return nil, fmt.Errorf("scan depth info: %w", err)
			}
			var parentPtr *string
			if parentID.Valid && parentID.String != "" {
				parentPtr = &parentID.String
			}
			execInfos = append(execInfos, execDepthInfo{
				executionID:       execID,
				parentExecutionID: parentPtr,
			})
		}

		// Compute max depth
		summary.MaxDepth = computeMaxDepth(execInfos)
	}

	return summary, nil
}

type execDepthInfo struct {
	executionID       string
	parentExecutionID *string
}

// computeMaxDepth calculates the maximum depth from parent-child relationships
func computeMaxDepth(execInfos []execDepthInfo) int {
	if len(execInfos) == 0 {
		return 0
	}

	// Build a map for quick lookup
	depthMap := make(map[string]int)

	// Build parent-to-children mapping
	childrenMap := make(map[string][]string)
	var roots []string

	for _, info := range execInfos {
		if info.parentExecutionID == nil || *info.parentExecutionID == "" {
			roots = append(roots, info.executionID)
			depthMap[info.executionID] = 0
		} else {
			parent := *info.parentExecutionID
			childrenMap[parent] = append(childrenMap[parent], info.executionID)
		}
	}

	// BFS to compute depths
	queue := make([]string, len(roots))
	copy(queue, roots)
	maxDepth := 0

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentDepth := depthMap[current]
		if currentDepth > maxDepth {
			maxDepth = currentDepth
		}

		for _, child := range childrenMap[current] {
			depthMap[child] = currentDepth + 1
			queue = append(queue, child)
		}
	}

	return maxDepth
}

// assignTimeValue parses diverse database timestamp encodings into a time.Time.
func assignTimeValue(dest *time.Time, value interface{}) error {
	if dest == nil {
		return fmt.Errorf("nil destination provided for time assignment")
	}
	parsed, err := parseDBTime(value)
	if err != nil {
		return err
	}
	*dest = parsed
	return nil
}

// parseDBTime normalizes the common representations emitted by SQLite and Postgres drivers.
func parseDBTime(value interface{}) (time.Time, error) {
	switch v := value.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		return v.UTC(), nil
	case string:
		return parseTimeString(v)
	case []byte:
		return parseTimeString(string(v))
	case sql.NullTime:
		if v.Valid {
			return v.Time.UTC(), nil
		}
		return time.Time{}, nil
	case sql.NullString:
		if v.Valid {
			return parseTimeString(v.String)
		}
		return time.Time{}, nil
	default:
		return time.Time{}, fmt.Errorf("unsupported time value type %T", value)
	}
}

var supportedTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999-07:00", // PostgreSQL timestamp with timezone
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05-07:00", // PostgreSQL timestamp with timezone (no microseconds)
	"2006-01-02 15:04:05",
}

func parseTimeString(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}

	for _, layout := range supportedTimeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC(), nil
		}
	}

	// Some SQLite builds omit the trailing Z on RFC3339 timestamps.
	if !strings.HasSuffix(value, "Z") && strings.Contains(value, "T") && !strings.ContainsAny(value, "+-") {
		if t, err := time.Parse(time.RFC3339Nano, value+"Z"); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time value %q", value)
}

// MarkStaleExecutions updates executions stuck in non-terminal states beyond the provided timeout.
func (ls *LocalStorage) MarkStaleExecutions(ctx context.Context, staleAfter time.Duration, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("context cancelled before marking stale executions: %w", err)
	}

	cutoff := time.Now().UTC().Add(-staleAfter)

	db := ls.requireSQLDB()
	rows, err := db.QueryContext(ctx, `
		SELECT execution_id, started_at
		FROM executions
		WHERE status IN ('running', 'pending', 'queued')
		  AND started_at <= ?
		ORDER BY started_at ASC
		LIMIT ?`, cutoff, limit)
	if err != nil {
		return 0, fmt.Errorf("query stale executions: %w", err)
	}
	defer rows.Close()

	type staleRecord struct {
		id        string
		startedAt time.Time
	}

	var stale []staleRecord
	for rows.Next() {
		var rec staleRecord
		if err := rows.Scan(&rec.id, &rec.startedAt); err != nil {
			return 0, fmt.Errorf("scan stale execution: %w", err)
		}
		stale = append(stale, rec)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate stale executions: %w", err)
	}

	if len(stale) == 0 {
		return 0, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin stale execution transaction: %w", err)
	}
	defer rollbackTx(tx, "MarkStaleExecutions")

	updateStmt, err := tx.PrepareContext(ctx, `
		UPDATE executions
		SET status = ?, error_message = ?, completed_at = ?, duration_ms = ?, updated_at = ?
		WHERE execution_id = ? AND status IN ('running', 'pending', 'queued')`)
	if err != nil {
		return 0, fmt.Errorf("prepare stale execution update: %w", err)
	}
	defer updateStmt.Close()

	now := time.Now().UTC()
	timeoutMessage := "execution timed out"

	updated := 0
	for _, rec := range stale {
		duration := now.Sub(rec.startedAt)
		if duration < 0 {
			duration = 0
		}
		durationMS := duration.Milliseconds()
		if durationMS < 0 {
			durationMS = 0
		}

		result, err := updateStmt.ExecContext(
			ctx,
			types.ExecutionStatusTimeout,
			timeoutMessage,
			now,
			durationMS,
			now,
			rec.id,
		)
		if err != nil {
			return 0, fmt.Errorf("update stale execution %s: %w", rec.id, err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("rows affected for execution %s: %w", rec.id, err)
		}
		if rowsAffected > 0 {
			updated++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit stale execution transaction: %w", err)
	}

	return updated, nil
}

func scanExecution(scanner interface {
	Scan(dest ...interface{}) error
}) (*types.Execution, error) {
	var (
		exec                         types.Execution
		parentExecutionID, sessionID sql.NullString
		actorID                      sql.NullString
		inputURI                     sql.NullString
		resultURI                    sql.NullString
		inputPayload                 []byte
		resultPayload                []byte
		errorMessage                 sql.NullString
		completedAt                  sql.NullTime
		durationMS                   sql.NullInt64
	)

	err := scanner.Scan(
		&exec.ExecutionID,
		&exec.RunID,
		&parentExecutionID,
		&exec.AgentNodeID,
		&exec.ReasonerID,
		&exec.NodeID,
		&exec.Status,
		&inputPayload,
		&resultPayload,
		&errorMessage,
		&inputURI,
		&resultURI,
		&sessionID,
		&actorID,
		&exec.StartedAt,
		&completedAt,
		&durationMS,
		&exec.CreatedAt,
		&exec.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan execution: %w", err)
	}

	if parentExecutionID.Valid {
		exec.ParentExecutionID = &parentExecutionID.String
	}
	if sessionID.Valid {
		exec.SessionID = &sessionID.String
	}
	if actorID.Valid {
		exec.ActorID = &actorID.String
	}
	exec.InputPayload = append(json.RawMessage(nil), inputPayload...)
	if len(resultPayload) > 0 {
		exec.ResultPayload = append(json.RawMessage(nil), resultPayload...)
	}
	if errorMessage.Valid {
		exec.ErrorMessage = &errorMessage.String
	}
	if inputURI.Valid {
		exec.InputURI = &inputURI.String
	}
	if resultURI.Valid {
		exec.ResultURI = &resultURI.String
	}
	if completedAt.Valid {
		t := completedAt.Time
		exec.CompletedAt = &t
	}
	if durationMS.Valid {
		val := durationMS.Int64
		exec.DurationMS = &val
	}

	return &exec, nil
}

func (ls *LocalStorage) enrichExecutionWebhook(ctx context.Context, exec *types.Execution, includeEvents bool) {
	if exec == nil {
		return
	}

	registered, err := ls.HasExecutionWebhook(ctx, exec.ExecutionID)
	if err != nil {
		logger.Logger.Warn().
			Err(err).
			Str("execution_id", exec.ExecutionID).
			Msg("could not determine webhook registration state")
		return
	}

	exec.WebhookRegistered = registered
	if !registered || !includeEvents {
		return
	}

	events, err := ls.ListExecutionWebhookEvents(ctx, exec.ExecutionID)
	if err != nil {
		logger.Logger.Warn().
			Err(err).
			Str("execution_id", exec.ExecutionID).
			Msg("failed to load execution webhook events")
		return
	}
	exec.WebhookEvents = events
}

func (ls *LocalStorage) populateWebhookRegistration(ctx context.Context, executions []*types.Execution) {
	if len(executions) == 0 {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	ids := make([]string, 0, len(executions))
	for _, exec := range executions {
		if exec == nil {
			continue
		}
		ids = append(ids, exec.ExecutionID)
	}

	registeredMap, err := ls.ListExecutionWebhooksRegistered(ctx, ids)
	if err != nil {
		logger.Logger.Warn().Err(err).Msg("failed to load webhook registration states")
		return
	}

	for _, exec := range executions {
		if exec == nil {
			continue
		}
		exec.WebhookRegistered = registeredMap[exec.ExecutionID]
	}
}

func bytesOrNil(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	return []byte(raw)
}
