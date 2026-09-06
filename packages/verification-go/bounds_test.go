package verification

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParserNodeAndEnvelopeBounds(t *testing.T) {
	group := "[" + strings.Repeat("0,", 99) + "0]"
	raw := "[" + strings.Repeat(group+",", 999) + group + "]"
	if _, err := parseJSON([]byte(raw)); err == nil {
		t.Fatal("node budget not enforced")
	}
	v, _, key := small(t)
	padding := make([]byte, MaxEnvelopeBytes+1)
	if _, err := VerifyEnvelope(padding, key); !errors.Is(err, ErrSchema) {
		t.Fatal("envelope budget not enforced")
	}
	// One canonical base64url signature has precisely 86 characters with zero
	// trailing pad bits. Every disallowed last character must be rejected.
	document := object(t, v.Document)
	signature := document["signature"].(map[string]any)
	encoded := signature["value"].(string)
	for _, last := range []byte{'B', '/', '=', '+'} {
		signature["value"] = encoded[:85] + string(last)
		if _, err := VerifyEnvelope(marshal(t, document), key); !errors.Is(err, ErrSignature) {
			t.Fatalf("signature encoding accepted: %v", err)
		}
	}
}
func FuzzRawEnvelopeDoesNotPanic(f *testing.F) {
	for _, seed := range []string{"{}", "null", `{"a":1,"a":2}`, `{"x":"\ud800"}`, `[1.0,1e3]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxEnvelopeBytes+1 {
			return
		}
		_, err := VerifyEnvelope(raw, make([]byte, 32))
		if err != nil {
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("untyped failure: %v", err)
			}
		}
		value, parseErr := parseJSON(raw)
		if parseErr == nil && json.Valid(raw) {
			// Canonicalization rejects non-integral numbers but must never panic.
			_, _ = canonicalJSON(value)
		}
	})
}
