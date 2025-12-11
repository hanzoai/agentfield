package webhooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// ExtractEventID returns the value at the configured JSON pointer for idempotency.
// If the pointer is empty or the path cannot be resolved, an empty string is returned.
func ExtractEventID(body []byte, pointer string) (string, error) {
	if strings.TrimSpace(pointer) == "" {
		return "", nil
	}

	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse webhook payload: %w", err)
	}

	value, found := getByPointer(payload, pointer)
	if !found {
		return "", nil
	}

	switch v := value.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	default:
		return fmt.Sprint(v), nil
	}
}

// MapPayload applies the trigger mapping configuration to the webhook payload.
func MapPayload(body []byte, trigger *types.WebhookTrigger) (map[string]interface{}, error) {
	if trigger == nil {
		return nil, fmt.Errorf("trigger configuration is required")
	}

	var payload interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parse webhook payload: %w", err)
	}

	root, ok := payload.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("webhook payload must be a JSON object")
	}

	switch trigger.Mode {
	case "", types.MappingModePassthrough:
		return root, nil
	case types.MappingModeSelect, types.MappingModeRemap:
		return mapWithConfig(root, trigger)
	default:
		return nil, fmt.Errorf("unsupported mapping mode %q", trigger.Mode)
	}
}

// HashPayload returns a stable SHA256 hash of the raw payload with a prefix for clarity.
func HashPayload(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HashMappedInput returns a SHA256 hash of the mapped input after JSON encoding.
func HashMappedInput(mapped map[string]interface{}) (string, error) {
	encoded, err := json.Marshal(mapped)
	if err != nil {
		return "", fmt.Errorf("encode mapped input: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func mapWithConfig(payload map[string]interface{}, trigger *types.WebhookTrigger) (map[string]interface{}, error) {
	result := make(map[string]interface{}, len(trigger.FieldMappings)+len(trigger.Defaults))

	for field, pointer := range trigger.FieldMappings {
		value, found := getByPointer(payload, pointer)
		if !found {
			return nil, fmt.Errorf("json pointer %q not found in payload", pointer)
		}
		result[field] = value
	}

	for key, value := range trigger.Defaults {
		if _, exists := result[key]; !exists {
			result[key] = value
		}
	}

	if len(trigger.TypeCoercions) == 0 {
		return result, nil
	}

	for field, targetType := range trigger.TypeCoercions {
		value, exists := result[field]
		if !exists {
			continue
		}
		coerced, err := coerceValue(value, targetType)
		if err != nil {
			return nil, fmt.Errorf("type coercion for field %q failed: %w", field, err)
		}
		result[field] = coerced
	}

	return result, nil
}

func getByPointer(data interface{}, pointer string) (interface{}, bool) {
	if pointer == "" || pointer == "/" {
		return data, true
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}

	current := data
	segments := strings.Split(pointer[1:], "/")
	for _, raw := range segments {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")

		switch typed := current.(type) {
		case map[string]interface{}:
			next, ok := typed[token]
			if !ok {
				return nil, false
			}
			current = next
		case []interface{}:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}

	return current, true
}

func coerceValue(value interface{}, targetType string) (interface{}, error) {
	switch strings.ToLower(targetType) {
	case "int", "integer":
		return coerceInt(value)
	case "float", "float64", "double":
		return coerceFloat(value)
	case "bool", "boolean":
		return coerceBool(value)
	case "string":
		return fmt.Sprint(value), nil
	default:
		return nil, fmt.Errorf("unsupported target type %q", targetType)
	}
}

func coerceInt(value interface{}) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			f, ferr := v.Float64()
			if ferr != nil {
				return 0, fmt.Errorf("parse number: %w", ferr)
			}
			return int64(f), nil
		}
		return i, nil
	case string:
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse int from string: %w", err)
		}
		return i, nil
	default:
		return 0, fmt.Errorf("cannot coerce %T to int", value)
	}
}

func coerceFloat(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case json.Number:
		return v.Float64()
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("parse float from string: %w", err)
		}
		return f, nil
	default:
		return 0, fmt.Errorf("cannot coerce %T to float", value)
	}
}

func coerceBool(value interface{}) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(strings.ToLower(v)))
		if err != nil {
			return false, fmt.Errorf("parse bool from string: %w", err)
		}
		return b, nil
	default:
		return false, fmt.Errorf("cannot coerce %T to bool", value)
	}
}
