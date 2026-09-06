package verification

import (
	"errors"
	"fmt"
	"testing"
)

// Derive negative cases from the authoritative schema, not a hand-maintained
// subset of envelope fields. Valid golden fixtures exercise both trust branches.
func TestAuthoritativeSchemaKeywordBoundaries(t *testing.T) {
	v, _, key := small(t)
	root := object(t, schemaBytes)
	resolve := func(schema map[string]any) map[string]any {
		if ref, ok := schema["$ref"].(string); ok {
			return root["$defs"].(map[string]any)[ref[len("#/$defs/"):]].(map[string]any)
		}
		return schema
	}
	count := 0
	reject := func(path []any, value any, keyword string) {
		t.Helper()
		doc := object(t, v.Document)
		setPath(t, doc, path, value)
		_, err := VerifyEnvelope(marshal(t, doc), key)
		want := ErrSchema
		if len(path) == 2 && path[0] == "signature" && path[1] == "value" {
			want = ErrSignature
		}
		if !errors.Is(err, want) {
			t.Fatalf("%v %s accepted or misclassified: %v", path, keyword, err)
		}
		count++
	}
	var walk func(map[string]any, any, []any)
	walk = func(schema map[string]any, value any, path []any) {
		schema = resolve(schema)
		if len(path) > 0 {
			reject(path, nil, "type")
		}
		if _, ok := schema["const"]; ok {
			reject(path, "unsupported", "const")
		}
		if _, ok := schema["enum"]; ok {
			reject(path, "unsupported", "enum")
		}
		if _, ok := schema["pattern"]; ok {
			reject(path, "\x00", "pattern")
		}
		if n, ok := schema["minimum"].(float64); ok {
			reject(path, n-1, "minimum")
		}
		if n, ok := schema["maximum"].(float64); ok {
			reject(path, n+1, "maximum")
		}
		if n, ok := schema["maxLength"].(float64); ok {
			reject(path, string(make([]byte, int(n)+1)), "maxLength")
		}
		if _, ok := schema["minLength"]; ok {
			reject(path, "", "minLength")
		}
		if _, ok := schema["format"]; ok {
			reject(path, "2026-02-30T12:00:00Z", "format")
		}
		switch value := value.(type) {
		case map[string]any:
			properties, ok := schema["properties"].(map[string]any)
			if !ok {
				t.Fatal("missing object properties")
			}
			for name, child := range value {
				walk(properties[name].(map[string]any), child, append(slicesClone(path), name))
			}
		case []any:
			if n, ok := schema["minItems"].(float64); ok && n > 0 {
				reject(path, []any{}, "minItems")
			}
			if n, ok := schema["maxItems"].(float64); ok {
				array := make([]any, int(n)+1)
				for i := range array {
					array[i] = value[0]
				}
				reject(path, array, "maxItems")
			}
			for i, child := range value {
				walk(schema["items"].(map[string]any), child, append(slicesClone(path), float64(i)))
			}
		}
	}
	walk(root, object(t, v.Document), nil)
	if count < 150 {
		t.Fatalf("unexpected schema coverage: %d", count)
	}
	t.Logf("%d schema-derived negative mutations", count)
}
func TestMalformedEnvelopeNeverReadsArtifact(t *testing.T) {
	v, _, key := small(t)
	for name, raw := range map[string][]byte{
		"duplicate":      append([]byte(`{"mediaType":"ignored",`), v.Document[1:]...),
		"BOM":            append([]byte{0xef, 0xbb, 0xbf}, v.Document...),
		"trailing":       append(append([]byte(nil), v.Document...), []byte("{}")...),
		"invalid utf8":   []byte("{\"x\":\"\xff\"}"),
		"lone surrogate": []byte("{\"x\":\"\\ud800\"}"),
	} {
		t.Run(name, func(t *testing.T) {
			reads := 0
			_, err := VerifyArtifact(raw, key, readerFunc(func([]byte) (int, error) { reads++; return 0, fmt.Errorf("must not read") }))
			if !errors.Is(err, ErrSchema) || reads != 0 {
				t.Fatalf("%v reads %d", err, reads)
			}
		})
	}
}
