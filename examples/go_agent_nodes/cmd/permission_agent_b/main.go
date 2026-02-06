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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Agent-Field/agentfield/sdk/go/agent"
)

// registerDID calls the control plane DID register API to obtain DID credentials.
func registerDID(agentFieldURL, nodeID string) (did string, privateKeyJWK string, err error) {
	payload, _ := json.Marshal(map[string]any{
		"agent_node_id": nodeID,
		"reasoners":     []any{},
		"skills":        []any{},
	})

	resp, err := http.Post(agentFieldURL+"/api/v1/did/register", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", "", fmt.Errorf("DID register request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("DID register returned %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Success         bool `json:"success"`
		IdentityPackage struct {
			AgentDID struct {
				DID           string `json:"did"`
				PrivateKeyJWK string `json:"private_key_jwk"`
			} `json:"agent_did"`
		} `json:"identity_package"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("failed to parse DID register response: %w", err)
	}
	if !result.Success {
		return "", "", fmt.Errorf("DID registration failed")
	}

	return result.IdentityPackage.AgentDID.DID, result.IdentityPackage.AgentDID.PrivateKeyJWK, nil
}

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

	nodeID := "go-perm-target"

	// Auto-provision DID credentials from the control plane
	did, privateKeyJWK, err := registerDID(agentFieldURL, nodeID)
	if err != nil {
		log.Printf("WARNING: DID registration failed: %v (running without DID auth)", err)
	} else {
		fmt.Printf("DID: %s\n", did)
	}

	cfg := agent.Config{
		NodeID:        nodeID,
		Version:       "1.0.0",
		AgentFieldURL: agentFieldURL,
		Token:         os.Getenv("AGENTFIELD_TOKEN"),
		ListenAddress: listenAddr,
		PublicURL:     publicURL,
		DID:           did,
		PrivateKeyJWK: privateKeyJWK,
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
