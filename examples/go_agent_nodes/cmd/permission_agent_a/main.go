// Permission Agent A (Caller) — Go SDK
//
// A normal agent that tries to call go-perm-target (a protected agent).
// Used to test the VC authorization system with the Go SDK.
//
// Test flow:
//  1. Start control plane with authorization enabled
//  2. Start go-perm-target (permission_agent_b)
//  3. Start go-perm-caller (this agent)
//  4. POST /api/v1/execute/go-perm-caller.call_data_service
//     -> Calls go-perm-target.query_data via the control plane
//     -> Should be denied (403) until an admin approves the permission
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
		listenAddr = ":8003"
	}

	publicURL := strings.TrimSpace(os.Getenv("AGENT_PUBLIC_URL"))
	if publicURL == "" {
		publicURL = "http://localhost" + listenAddr
	}

	cfg := agent.Config{
		NodeID:            "go-perm-caller",
		Version:           "1.0.0",
		AgentFieldURL:     agentFieldURL,
		Token:             os.Getenv("AGENTFIELD_TOKEN"),
		InternalToken:     os.Getenv("AGENTFIELD_INTERNAL_TOKEN"),
		ListenAddress:     listenAddr,
		PublicURL:         publicURL,
		EnableDID:         true, // Auto-register DID during Initialize()
		VCEnabled:         true, // Generate VCs for audit trail
		RequireOriginAuth: true, // Only the control plane can invoke reasoners
	}

	a, err := agent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Simple health check — no cross-agent call, should always work.
	a.RegisterReasoner("ping", func(ctx context.Context, input map[string]any) (any, error) {
		return map[string]any{
			"status": "ok",
			"agent":  "go-perm-caller",
		}, nil
	},
		agent.WithDescription("Simple health check"),
		agent.WithVCEnabled(false), // No VC needed for health checks
	)

	// Calls go-perm-target.query_data through the control plane.
	// This triggers the permission check middleware since go-perm-target
	// is a protected agent (matched by agent_id pattern).
	a.RegisterReasoner("call_data_service", func(ctx context.Context, input map[string]any) (any, error) {
		query := fmt.Sprintf("%v", input["query"])
		if query == "" || query == "<nil>" {
			query = "SELECT * FROM data"
		}

		result, err := a.Call(ctx, "go-perm-target.query_data", map[string]any{
			"query": query,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to call go-perm-target.query_data: %w", err)
		}

		return map[string]any{
			"source":            "go-perm-caller",
			"delegation_result": result,
		}, nil
	},
		agent.WithDescription("Calls go-perm-target.query_data through the control plane"),
	)

	fmt.Println("Permission Agent A (Caller) — Go SDK")
	fmt.Println("Node: go-perm-caller")
	fmt.Printf("Server: %s\n", agentFieldURL)

	if err := a.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
