package verification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../../schemas/fixtures/attestation"

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func object(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type smallVector struct {
	Document                                                          json.RawMessage
	ArtifactHex, PublicKeyHex, CanonicalStatement, SigningInputSHA256 string
}

func small(t *testing.T) (smallVector, []byte, ed25519.PublicKey) {
	t.Helper()
	var v smallVector
	if err := json.Unmarshal(readFixture(t, "interop/small-artifact.json"), &v); err != nil {
		t.Fatal(err)
	}
	return v, decodeHex(t, v.ArtifactHex), decodeHex(t, v.PublicKeyHex)
}
func setPath(t *testing.T, doc map[string]any, path []any, value any) {
	t.Helper()
	var at any = doc
	for _, part := range path[:len(path)-1] {
		switch p := part.(type) {
		case string:
			at = at.(map[string]any)[p]
		case float64:
			at = at.([]any)[int(p)]
		}
	}
	switch p := path[len(path)-1].(type) {
	case string:
		at.(map[string]any)[p] = value
	case float64:
		at.([]any)[int(p)] = value
	}
}
func TestSharedGoldenVectors(t *testing.T) {
	for _, name := range []string{"hosted", "self-hosted"} {
		t.Run(name, func(t *testing.T) {
			var v struct{ PublicKeyHex, PrivateKeySeedHex, CanonicalStatementSHA256, SigningInputSHA256, SignatureBase64URL string }
			if err := json.Unmarshal(readFixture(t, "vectors/"+name+".json"), &v); err != nil {
				t.Fatal(err)
			}
			raw := readFixture(t, "valid/"+name+".json")
			key := decodeHex(t, v.PublicKeyHex)
			got, err := VerifyEnvelope(raw, key)
			if err != nil {
				t.Fatal(err)
			}
			doc := object(t, raw)
			canonical, err := canonicalJSON(doc["statement"])
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(canonical)
			if hex.EncodeToString(digest[:]) != v.CanonicalStatementSHA256 {
				t.Fatal("canonical mismatch")
			}
			input := append([]byte("Provenance Attestation v1\n"+got.KeyID+"\n"), canonical...)
			digest = sha256.Sum256(input)
			if hex.EncodeToString(digest[:]) != v.SigningInputSHA256 {
				t.Fatal("signing input mismatch")
			}
			seed := decodeHex(t, v.PrivateKeySeedHex)
			sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), input)
			if !ed25519.Verify(key, input, sig) || base64.RawURLEncoding.EncodeToString(sig) != v.SignatureBase64URL {
				t.Fatal("test-only deterministic signing mismatch")
			}
			for _, mutation := range []func(map[string]any){
				func(d map[string]any) {
					d["statement"].(map[string]any)["subject"].(map[string]any)["sizeBytes"] = float64(1)
				},
				func(d map[string]any) { d["signature"].(map[string]any)["keyId"] = got.KeyID + "-relabeled" },
			} {
				doc = object(t, raw)
				mutation(doc)
				if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSignature) {
					t.Fatalf("tampering %v", err)
				}
			}
		})
	}
}
func TestSharedInvalidSchemaCases(t *testing.T) {
	var cases []struct {
		Name  string
		Path  []any
		Value any
	}
	if err := json.Unmarshal(readFixture(t, "invalid/cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	_, _, key := small(t)
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			doc := object(t, readFixture(t, "valid/hosted.json"))
			setPath(t, doc, test.Path, test.Value)
			_, err := VerifyEnvelope(marshal(t, doc), key)
			want := ErrSchema
			if test.Name == "padded or truncated signature" {
				want = ErrSignature
			}
			if !errors.Is(err, want) {
				t.Fatalf("want %v got %v", want, err)
			}
		})
	}
}
func TestEmbeddedSchemaIsAuthoritativeAndOffline(t *testing.T) {
	authoritative, err := os.ReadFile("../../schemas/attestation/v1/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authoritative, schemaBytes) {
		t.Fatal("embedded schema drift")
	}
	if _, err := compiledSchema(); err != nil {
		t.Fatal(err)
	}
	if _, err := (offlineLoader{}).Load("file:///secret"); err == nil {
		t.Fatal("loader accepted filesystem")
	}
	if _, err := (offlineLoader{}).Load("https://example.invalid"); err == nil {
		t.Fatal("loader accepted network")
	}
}
func TestRawJSONAndCanonicalParity(t *testing.T) {
	var cases []struct {
		Name, JSON, Canonical string
		Valid                 bool
	}
	if err := json.Unmarshal(readFixture(t, "interop/raw-json.json"), &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			value, err := parseJSON([]byte(test.JSON))
			if !test.Valid {
				if err == nil {
					t.Fatal("invalid raw JSON accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalJSON(value)
			if err != nil || string(canonical) != test.Canonical {
				t.Fatalf("%q %v want %q", canonical, err, test.Canonical)
			}
		})
	}
	for _, raw := range [][]byte{{0xff}, []byte("{\"x\":\"\xff\"}"), []byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)), []byte("[" + strings.Repeat("0,", 1000) + "0]"), bytes.Repeat([]byte(" "), MaxEnvelopeBytes+1)} {
		if _, err := parseJSON(raw); err == nil {
			t.Fatal("unbounded/invalid raw JSON accepted")
		}
	}
}
func TestSmallArtifactAndNumericRepresentations(t *testing.T) {
	v, artifact, key := small(t)
	result, err := VerifyArtifact(v.Document, key, bytes.NewReader(artifact))
	if err != nil || result.SizeBytes != int64(len(artifact)) {
		t.Fatalf("%+v %v", result, err)
	}
	doc := object(t, v.Document)
	canonical, _ := canonicalJSON(doc["statement"])
	if string(canonical) != v.CanonicalStatement {
		t.Fatal("cross-language Unicode canonicalization")
	}
	raw := marshal(t, doc)
	for _, number := range []string{"33.0", "3.3e1"} {
		changed := bytes.Replace(raw, []byte("\"sizeBytes\":33"), []byte("\"sizeBytes\":"+number), 1)
		if bytes.Equal(changed, raw) {
			t.Fatal("numeric mutation did not change input")
		}
		if _, err := VerifyArtifact(changed, key, bytes.NewReader(artifact)); err != nil {
			t.Fatal(err)
		}
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

type ownedReader struct {
	*bytes.Reader
	closed bool
}

func (r *ownedReader) Close() error { r.closed = true; return nil }
func TestAuthenticateBeforeReadAndErrorClasses(t *testing.T) {
	v, artifact, key := small(t)
	tests := []struct {
		name   string
		mutate func(map[string]any)
		key    []byte
		want   error
	}{
		{"schema", func(d map[string]any) { d["extra"] = true }, key, ErrSchema},
		{"key", func(map[string]any) {}, make([]byte, 31), ErrKey},
		{"private key", func(map[string]any) {}, make([]byte, 64), ErrKey},
		{"wrong key", func(map[string]any) {}, make([]byte, 32), ErrSignature},
		{"signature encoding", func(d map[string]any) { d["signature"].(map[string]any)["value"] = "AAAA==" }, key, ErrSignature},
		{"mixed schema and signature", func(d map[string]any) { d["extra"] = true; d["signature"].(map[string]any)["value"] = "AAAA==" }, key, ErrSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc := object(t, v.Document)
			test.mutate(doc)
			reads := 0
			_, err := VerifyArtifact(marshal(t, doc), test.key, readerFunc(func([]byte) (int, error) { reads++; return 0, io.EOF }))
			if !errors.Is(err, test.want) || reads != 0 {
				t.Fatalf("%v reads%d", err, reads)
			}
		})
	}
	reader := &ownedReader{Reader: bytes.NewReader(artifact)}
	if _, err := VerifyArtifact(v.Document, key, reader); err != nil || reader.closed {
		t.Fatalf("ownership %v", err)
	}
	for _, test := range []struct {
		name string
		data []byte
		want error
	}{
		{"truncated", artifact[:len(artifact)-1], ErrSize}, {"appended", append(bytes.Clone(artifact), 1, 2, 3), ErrSize},
		{"digest", bytes.Repeat([]byte{0}, len(artifact)), ErrDigest},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := &ownedReader{Reader: bytes.NewReader(test.data)}
			_, err := VerifyArtifact(v.Document, key, r)
			if !errors.Is(err, test.want) || r.closed {
				t.Fatalf("%v closed%v", err, r.closed)
			}
			if test.name == "appended" && r.Len() != 2 {
				t.Fatalf("read beyond first excess byte: %d", r.Len())
			}
		})
	}
}
func TestReaderErrorsShortReadsAndMutationIsolation(t *testing.T) {
	v, artifact, key := small(t)
	position := 0
	got, err := VerifyArtifact(v.Document, key, readerFunc(func(p []byte) (int, error) {
		if position == len(artifact) {
			return 0, io.EOF
		}
		p[0] = artifact[position]
		position++
		return 1, nil
	}))
	if err != nil || got.SizeBytes != int64(len(artifact)) {
		t.Fatalf("%+v %v", got, err)
	}
	for _, r := range []io.Reader{
		readerFunc(func([]byte) (int, error) { return 0, errors.New("hostile-reader-error") }),
		readerFunc(func([]byte) (int, error) { return 0, nil }),
		readerFunc(func(p []byte) (int, error) { return len(p) + 1, nil }),
		readerFunc(func([]byte) (int, error) { return -1, nil }),
		nil,
	} {
		if _, err := VerifyArtifact(v.Document, key, r); !errors.Is(err, ErrRead) || strings.Contains(err.Error(), "hostile-reader-error") {
			t.Fatalf("read error %v", err)
		}
	}
	original := bytes.NewReader(artifact)
	document := bytes.Clone(v.Document)
	mutableKey := bytes.Clone(key)
	got, err = VerifyArtifact(document, mutableKey, readerFunc(func(p []byte) (int, error) { clear(document); clear(mutableKey); return original.Read(p) }))
	if err != nil || got.SizeBytes != int64(len(artifact)) {
		t.Fatalf("mutable inputs affected verified identity: %v", err)
	}
}
func TestAllRequiredFieldsAndUnknownObjects(t *testing.T) {
	raw, _, key := small(t)
	// Walk the valid envelope: every object is closed and every currently present
	// property is required by v1. Exercise nested objects, including array items.
	var walk func(any, []any)
	walk = func(value any, path []any) {
		switch v := value.(type) {
		case map[string]any:
			for name, child := range v {
				doc := object(t, raw.Document)
				var at any = doc
				for _, p := range path {
					switch p := p.(type) {
					case string:
						at = at.(map[string]any)[p]
					case float64:
						at = at.([]any)[int(p)]
					}
				}
				delete(at.(map[string]any), name)
				if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSchema) {
					t.Fatalf("missing %v/%s: %v", path, name, err)
				}
				next := append(slicesClone(path), name)
				walk(child, next)
			}
			doc := object(t, raw.Document)
			var at any = doc
			for _, p := range path {
				switch p := p.(type) {
				case string:
					at = at.(map[string]any)[p]
				case float64:
					at = at.([]any)[int(p)]
				}
			}
			at.(map[string]any)["unknown"] = true
			if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSchema) {
				t.Fatalf("unknown %v: %v", path, err)
			}
		case []any:
			for i, child := range v {
				walk(child, append(slicesClone(path), float64(i)))
			}
		}
	}
	walk(object(t, raw.Document), nil)
}
func slicesClone(v []any) []any { return append([]any(nil), v...) }
func TestSchemaConstraints(t *testing.T) {
	v, _, key := small(t)
	tests := []struct {
		path  []any
		value any
	}{
		{[]any{"statement", "subject", "sizeBytes"}, 0}, {[]any{"statement", "subject", "sizeBytes"}, 1073741825}, {[]any{"statement", "subject", "sizeBytes"}, 1.5},
		{[]any{"statement", "verifiedAt"}, "2026-02-30T00:00:00Z"}, {[]any{"statement", "verifiedAt"}, "2026-01-01T00:00:00+00:00"},
		{[]any{"statement", "environments"}, []any{}}, {[]any{"statement", "assertions"}, []any{}},
		{[]any{"statement", "runner", "hosting"}, "other"}, {[]any{"statement", "runner", "trust"}, "organization-reported"},
		{[]any{"statement", "runner", "sandbox", "kind"}, "process"},
		{[]any{"statement", "subject", "name"}, "../a.jar"}, {[]any{"statement", "source", "ref"}, "refs/heads/bad ref"},
		{[]any{"statement", "source", "commit"}, "main"}, {[]any{"signature", "canonicalization"}, "other"},
		{[]any{"signature", "keyId"}, "key\nnew"}, {[]any{"statement", "configuration", "digest", "value"}, strings.Repeat("A", 64)},
	}
	for _, test := range tests {
		doc := object(t, v.Document)
		setPath(t, doc, test.path, test.value)
		if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSchema) {
			t.Fatalf("%v: %v", test.path, err)
		}
	}
	for _, name := range []string{"dependencies", "environments", "assertions"} {
		doc := object(t, v.Document)
		statement := doc["statement"].(map[string]any)
		array := statement[name].([]any)
		if len(array) == 0 {
			t.Fatalf("fixture missing %s", name)
		}
		statement[name] = append(array, array[0])
		if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSchema) {
			t.Fatalf("duplicate %s: %v", name, err)
		}
	}
}
