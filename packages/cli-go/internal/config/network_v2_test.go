package config

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestVersionedNetworkSchemaAndGolden(t *testing.T) {
	raw, err := os.ReadFile("../../../../schemas/config/v2/schema.json")
	if err != nil || !bytes.Equal(raw, schemaV2) {
		t.Fatal("embedded v2 schema differs", err)
	}
	raw, err = os.ReadFile("../../../../schemas/fixtures/config/v2/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ Canonical, SHA256 string }
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("invalid vector")
	}
	d, err := Normalize([]byte(vector.Canonical))
	if err != nil || d.Normalized != vector.Canonical || d.Hash != vector.SHA256 {
		t.Fatal("v2 independent canonical/hash differs", err)
	}
	// Public HTTP snapshots are still v1. Valid v2 must not be relabelled by
	// submission, even if its release mode is otherwise executable.
	var submission map[string]any
	if json.Unmarshal([]byte(vector.Canonical), &submission) != nil {
		t.Fatal("fixture invalid")
	}
	submission["release"] = map[string]any{"mode": "test-only", "targets": []any{}}
	input, err := json.Marshal(submission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Normalize(input); err != nil {
		t.Fatal("valid test-only v2 refused by validator", err)
	}
	if _, err = Parse(input); err == nil {
		t.Fatal("v2 admitted through v1 submission boundary")
	}
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"mode", "unrestricted"}, {"permissions", []any{}}, {"maximumConnections", 0},
		{"maximumConnections", 1.5}, {"maximumBytesPerSecond", uint64(4294967296)},
		{"maximumConnections", true}, {"resolver", "customer.example"},
	} {
		var value map[string]any
		if json.Unmarshal([]byte(vector.Canonical), &value) != nil {
			t.Fatal("fixture invalid")
		}
		value["network"].(map[string]any)[tc.key] = tc.value
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Normalize(raw); err == nil {
			t.Fatalf("accepted invalid v2 %s", tc.key)
		}
	}
	for _, host := range []string{"localhost", "127.0.0.1", "0x7f.0.0.1", "0177.0.0.1", "*.example", "A.example", "a.example\n"} {
		var value map[string]any
		if json.Unmarshal([]byte(vector.Canonical), &value) != nil {
			t.Fatal("fixture invalid")
		}
		value["network"].(map[string]any)["permissions"].([]any)[0].(map[string]any)["hostname"] = host
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Normalize(raw); err == nil {
			t.Fatal("accepted invalid hostname")
		}
	}
}
