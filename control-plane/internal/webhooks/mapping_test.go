package webhooks

import (
	"testing"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestExtractEventID(t *testing.T) {
	body := []byte(`{
		"headers": {"X-Request-ID": "abc-123"},
		"payload": {"id": "inner"}
	}`)

	id, err := ExtractEventID(body, "/headers/X-Request-ID")
	require.NoError(t, err)
	require.Equal(t, "abc-123", id)

	id, err = ExtractEventID(body, "/missing/path")
	require.NoError(t, err)
	require.Equal(t, "", id)

	id, err = ExtractEventID(body, "")
	require.NoError(t, err)
	require.Equal(t, "", id)
}

func TestMapPayloadPassthrough(t *testing.T) {
	body := []byte(`{"foo": 1, "bar": "baz"}`)
	trigger := &types.WebhookTrigger{Mode: types.MappingModePassthrough}

	mapped, err := MapPayload(body, trigger)
	require.NoError(t, err)
	require.Equal(t, float64(1), mapped["foo"])
	require.Equal(t, "baz", mapped["bar"])
}

func TestMapPayloadRemapWithCoercions(t *testing.T) {
	body := []byte(`{
		"pull_request": {
			"number": 42,
			"diff_url": "https://example.com/diff"
		},
		"repository": { "full_name": "org/repo" },
		"headers": { "X-Delivery": "evt-123" }
	}`)

	trigger := &types.WebhookTrigger{
		Mode: types.MappingModeRemap,
		FieldMappings: map[string]string{
			"url":       "/pull_request/diff_url",
			"repo":      "/repository/full_name",
			"pr_number": "/pull_request/number",
		},
		Defaults: map[string]interface{}{
			"auto_merge": false,
		},
		TypeCoercions: map[string]string{
			"pr_number": "int",
		},
	}

	mapped, err := MapPayload(body, trigger)
	require.NoError(t, err)

	require.Equal(t, "https://example.com/diff", mapped["url"])
	require.Equal(t, "org/repo", mapped["repo"])
	require.EqualValues(t, 42, mapped["pr_number"])
	require.Equal(t, false, mapped["auto_merge"])
}

func TestMapPayloadMissingField(t *testing.T) {
	body := []byte(`{"payload": {"id": "abc"}}`)
	trigger := &types.WebhookTrigger{
		Mode: types.MappingModeSelect,
		FieldMappings: map[string]string{
			"missing": "/does/not/exist",
		},
	}

	_, err := MapPayload(body, trigger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "json pointer")
}

func TestHashHelpers(t *testing.T) {
	body := []byte(`{"a":1}`)
	same := []byte(`{"a":1}`)
	other := []byte(`{"a":2}`)

	require.Equal(t, HashPayload(body), HashPayload(same))
	require.NotEqual(t, HashPayload(body), HashPayload(other))

	mapped := map[string]interface{}{
		"foo": "bar",
		"num": 1,
	}
	hashA, err := HashMappedInput(mapped)
	require.NoError(t, err)

	// Using a new map instance with the same data should produce the same hash.
	hashB, err := HashMappedInput(map[string]interface{}{
		"num": 1,
		"foo": "bar",
	})
	require.NoError(t, err)
	require.Equal(t, hashA, hashB)
}
