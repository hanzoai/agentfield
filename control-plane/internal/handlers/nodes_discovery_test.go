package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestNormalizeCandidateAddsDefaults(t *testing.T) {
	normalized, err := normalizeCandidate("example.com", "8080")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if normalized != "http://example.com:8080" {
		t.Fatalf("unexpected normalization: %s", normalized)
	}

	normalized, err = normalizeCandidate("https://example.com", "8080")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if normalized != "https://example.com:8080" {
		t.Fatalf("expected default port applied, got %s", normalized)
	}
}

func TestResolveCallbackCandidatesSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/mcp" || r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolved, normalized, results := resolveCallbackCandidates(
		context.Background(),
		[]string{srv.URL},
		"",
		true,
	)

	if resolved == "" {
		t.Fatalf("expected resolved callback URL")
	}
	if len(normalized) != 1 {
		t.Fatalf("expected exactly one normalized candidate, got %d", len(normalized))
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly one probe result, got %d", len(results))
	}
	if !results[0].Success {
		t.Fatalf("expected probe success, got %+v", results[0])
	}
}

func TestResolveCallbackCandidatesSkipsProbeWhenDisabled(t *testing.T) {
	var hits int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resolved, normalized, results := resolveCallbackCandidates(
		context.Background(),
		[]string{srv.URL},
		"",
		false,
	)

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("expected no probes when disabled, got %d requests", got)
	}
	if resolved != "" {
		t.Fatalf("expected no resolved URL when probes are disabled, got %s", resolved)
	}
	if len(normalized) != 1 {
		t.Fatalf("expected normalized candidates even when probes disabled, got %d", len(normalized))
	}
	if len(results) != 0 {
		t.Fatalf("expected no probe results when probing disabled, got %d", len(results))
	}
}
