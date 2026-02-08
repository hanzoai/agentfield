// Permission Agent B (Protected Target) — Go SDK
//
// A protected agent with multiple reasoners. Used to test that when an
// agent is protected by an agent_id rule, ALL of its reasoners are gated
// by the permission middleware — not just one.
//
// Reasoners:
//   - query_data    — simulates a data query
//   - update_record — simulates a record update
//   - get_schema    — returns the data schema
//
// All three should return 403 when called by an unapproved agent.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
)

func main() {
	agentFieldURL := strings.TrimSpace(os.Getenv("AGENTFIELD_URL"))
	if agentFieldURL == "" {
		agentFieldURL = "http://localhost:8080"
	}

	listenAddr := strings.TrimSpace(os.Getenv("AGENT_LISTEN_ADDR"))
	if listenAddr == "" {
		listenAddr = ":8004"
	}

	publicURL := strings.TrimSpace(os.Getenv("AGENT_PUBLIC_URL"))
	if publicURL == "" {
		publicURL = "http://localhost" + listenAddr
	}

	cfg := agent.Config{
		NodeID:            "go-perm-target",
		Version:           "1.0.0",
		AgentFieldURL:     agentFieldURL,
		Token:             os.Getenv("AGENTFIELD_TOKEN"),
		InternalToken:     os.Getenv("AGENTFIELD_INTERNAL_TOKEN"),
		ListenAddress:     listenAddr,
		PublicURL:         publicURL,
		EnableDID:         true, // Auto-register DID during Initialize()
		VCEnabled:         true, // Generate VCs for audit trail
		Tags:              []string{"sensitive", "data-service"},
		RequireOriginAuth: true, // Only the control plane can invoke reasoners
	}

	b, err := agent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Reasoner 1: query_data — simulates a data query.
	b.RegisterReasoner("query_data", func(ctx context.Context, input map[string]any) (any, error) {
		query := fmt.Sprintf("%v", input["query"])
		if query == "" || query == "<nil>" {
			query = "SELECT *"
		}

		return map[string]any{
			"status":  "success",
			"agent":   "go-perm-target",
			"query":   query,
			"results": []map[string]any{{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}},
			"message": fmt.Sprintf("Query executed: %s", query),
		}, nil
	},
		agent.WithDescription("Execute a data query. Protected operation."),
	)

	// Reasoner 2: update_record — simulates a record update.
	b.RegisterReasoner("update_record", func(ctx context.Context, input map[string]any) (any, error) {
		id := input["id"]
		data := input["data"]

		return map[string]any{
			"status":  "updated",
			"agent":   "go-perm-target",
			"id":      id,
			"data":    data,
			"message": fmt.Sprintf("Record %v updated successfully", id),
		}, nil
	},
		agent.WithDescription("Update a data record. Protected operation."),
	)

	// Reasoner 3: get_schema — returns the data schema.
	b.RegisterReasoner("get_schema", func(ctx context.Context, input map[string]any) (any, error) {
		return map[string]any{
			"status": "success",
			"agent":  "go-perm-target",
			"schema": map[string]any{
				"table": "records",
				"columns": []map[string]any{
					{"name": "id", "type": "integer", "primary_key": true},
					{"name": "name", "type": "text"},
					{"name": "created_at", "type": "timestamp"},
				},
			},
		}, nil
	},
		agent.WithDescription("Get the data schema. Protected operation."),
	)

	fmt.Println("Permission Agent B (Protected) — Go SDK")
	fmt.Println("Node: go-perm-target")
	fmt.Printf("Server: %s\n", agentFieldURL)
	fmt.Println("Reasoners: query_data, update_record, get_schema")

	if err := b.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
