package utils

import (
	cryptoRand "crypto/rand"
	"fmt"
	mathrand "math/rand"
	"time"
)

// GenerateWorkflowID generates a new workflow ID
func GenerateWorkflowID() string {
	timestamp := time.Now().Format("20060102_150405")
	random, err := generateRandomString(8)
	if err != nil {
		random = generateRandomStringInsecure(8)
	}
	return fmt.Sprintf("wf_%s_%s", timestamp, random)
}

// GenerateExecutionID generates a new execution ID
func GenerateExecutionID() string {
	timestamp := time.Now().Format("20060102_150405")
	random, err := generateRandomString(8)
	if err != nil {
		random = generateRandomStringInsecure(8)
	}
	return fmt.Sprintf("exec_%s_%s", timestamp, random)
}

// GenerateRunID generates a new workflow run ID.
func GenerateRunID() string {
	timestamp := time.Now().Format("20060102_150405")
	random, err := generateRandomString(8)
	if err != nil {
		random = generateRandomStringInsecure(8)
	}
	return fmt.Sprintf("run_%s_%s", timestamp, random)
}

// GenerateAgentFieldRequestID generates a new agentfield request ID
func GenerateAgentFieldRequestID() string {
	timestamp := time.Now().Format("20060102_150405")
	random, err := generateRandomString(8)
	if err != nil {
		random = generateRandomStringInsecure(8)
	}
	return fmt.Sprintf("req_%s_%s", timestamp, random)
}

// GenerateWebhookTriggerID generates an ID for inbound webhook triggers.
func GenerateWebhookTriggerID() string {
	random, err := generateRandomString(12)
	if err != nil {
		random = generateRandomStringInsecure(12)
	}
	return fmt.Sprintf("wht_%s", random)
}

// GenerateWebhookDeliveryID generates an ID for webhook deliveries.
func GenerateWebhookDeliveryID() string {
	random, err := generateRandomString(12)
	if err != nil {
		random = generateRandomStringInsecure(12)
	}
	return fmt.Sprintf("whd_%s", random)
}

// GenerateWebhookSecret generates a secret value shared with webhook senders.
func GenerateWebhookSecret() (string, error) {
	random, err := generateRandomString(24)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("whs_%s", random), nil
}

// ValidateWorkflowID validates a workflow ID format
func ValidateWorkflowID(workflowID string) bool {
	// Basic validation - can be enhanced later
	return len(workflowID) > 0 && len(workflowID) <= 255
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	if _, err := cryptoRand.Read(b); err != nil {
		return "", fmt.Errorf("unable to securely generate random string: %w", err)
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}

// generateRandomStringInsecure is a best-effort fallback for non-secret IDs if crypto/rand fails.
func generateRandomStringInsecure(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	src := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = charset[src.Intn(len(charset))]
	}
	return string(b)
}
