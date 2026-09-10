// Package verification independently verifies Provenance v1/v2 envelopes and
// caller-supplied artifact streams. It performs no network or filesystem access.
package verification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	ErrSchema    = errors.New("invalid attestation schema")
	ErrKey       = errors.New("invalid Ed25519 public key")
	ErrSignature = errors.New("invalid attestation signature")
	ErrSize      = errors.New("artifact size mismatch")
	ErrDigest    = errors.New("artifact digest mismatch")
	ErrRead      = errors.New("artifact read failed")
)

// Error distinguishes verification failures using errors.Is. Error text never
// includes document contents or the underlying reader error.
type Error struct {
	Kind                           error
	Cause                          error
	ExpectedSize, ObservedSize     int64
	ExpectedDigest, ObservedDigest string
}

func (e *Error) Error() string { return e.Kind.Error() }
func (e *Error) Unwrap() []error {
	if e.Cause != nil {
		return []error{e.Kind, e.Cause}
	}
	return []error{e.Kind}
}

// ArtifactIdentity describes the bytes bound by the signature.
type ArtifactIdentity struct {
	SizeBytes int64
	SHA256    string
}

// VerifiedEnvelope authenticates an envelope under the caller-selected key.
// It does not imply trusted key discovery, artifact possession, or test success.
type VerifiedEnvelope struct {
	KeyID    string
	Artifact ArtifactIdentity
}

//go:embed schema.json
var schemaBytes []byte

//go:embed schema-v2.json
var schemaV2Bytes []byte

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	return compileSchema(schemaBytes, "https://schemas.provenance.dev/attestation/v1/schema.json")
})
var compiledSchemaV2 = sync.OnceValues(func() (*jsonschema.Schema, error) {
	return compileSchema(schemaV2Bytes, "https://schemas.provenance.dev/attestation/v2/schema.json")
})

func compileSchema(raw []byte, id string) (*jsonschema.Schema, error) {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseLoader(offlineLoader{})
	compiler.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		re, err := regexp2.Compile(pattern, regexp2.ECMAScript)
		if err != nil {
			return nil, err
		}
		re.MatchTimeout = 100 * time.Millisecond
		return ecmaRegexp{re}, nil
	})
	if err := compiler.AddResource(id, document); err != nil {
		return nil, err
	}
	return compiler.Compile(id)
}

type offlineLoader struct{}

func (offlineLoader) Load(string) (any, error) {
	return nil, errors.New("external schema loading disabled")
}

type ecmaRegexp struct{ re *regexp2.Regexp }

func (r ecmaRegexp) MatchString(s string) bool {
	ok, err := r.re.MatchString(s)
	return err == nil && ok
}
func (r ecmaRegexp) String() string { return r.re.String() }

// VerifyEnvelope validates raw JSON and the complete authoritative v1 schema,
// then verifies the domain-separated Ed25519 signature. The key must be exactly
// 32 public bytes; callers are responsible for selecting a trusted key for keyId.
// Inputs are snapshotted before verification; callers must not race the call
// while those initial copies are made.
func VerifyEnvelope(document []byte, publicKey ed25519.PublicKey) (VerifiedEnvelope, error) {
	if len(document) > MaxEnvelopeBytes {
		return VerifiedEnvelope{}, &Error{Kind: ErrSchema}
	}
	raw := bytes.Clone(document)
	var key ed25519.PublicKey
	if len(publicKey) == ed25519.PublicKeySize {
		key = bytes.Clone(publicKey)
	}
	value, err := parseJSON(raw)
	if err != nil {
		return VerifiedEnvelope{}, &Error{Kind: ErrSchema}
	}
	schema, err := compiledSchema()
	domain := "Provenance Attestation v1\n"
	if envelope, ok := value.(map[string]any); ok && envelope["mediaType"] == "application/vnd.provenance.attestation.v2+json" {
		schema, err = compiledSchemaV2()
		domain = "Provenance Attestation v2\n"
	}
	if err != nil {
		return VerifiedEnvelope{}, &Error{Kind: ErrSchema}
	}
	if err = schema.Validate(value); err != nil {
		var invalid *jsonschema.ValidationError
		if errors.As(err, &invalid) && onlySignatureEncoding(invalid) {
			return VerifiedEnvelope{}, &Error{Kind: ErrSignature}
		}
		return VerifiedEnvelope{}, &Error{Kind: ErrSchema}
	}
	envelope := value.(map[string]any)
	signature := envelope["signature"].(map[string]any)
	// Schema validation precedes key and signature checks, as in the TS verifier.
	if len(key) != ed25519.PublicKeySize {
		return VerifiedEnvelope{}, &Error{Kind: ErrKey}
	}
	encoded := signature["value"].(string)
	sig, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return VerifiedEnvelope{}, &Error{Kind: ErrSignature}
	}
	keyID := signature["keyId"].(string)
	canonical, err := canonicalJSON(envelope["statement"])
	if err != nil {
		return VerifiedEnvelope{}, &Error{Kind: ErrSchema}
	}
	input := append([]byte(domain+keyID+"\n"), canonical...)
	if !ed25519.Verify(key, input, sig) {
		return VerifiedEnvelope{}, &Error{Kind: ErrSignature}
	}
	statement := envelope["statement"].(map[string]any)
	subject := statement["subject"].(map[string]any)
	digest := subject["digest"].(map[string]any)
	return VerifiedEnvelope{KeyID: keyID, Artifact: ArtifactIdentity{SizeBytes: int64(subject["sizeBytes"].(float64)), SHA256: digest["value"].(string)}}, nil
}

func onlySignatureEncoding(invalid *jsonschema.ValidationError) bool {
	if len(invalid.Causes) == 0 {
		return len(invalid.InstanceLocation) == 2 &&
			invalid.InstanceLocation[0] == "signature" && invalid.InstanceLocation[1] == "value"
	}
	for _, cause := range invalid.Causes {
		if !onlySignatureEncoding(cause) {
			return false
		}
	}
	return true
}

// VerifyArtifact authenticates before the first Read, then counts and hashes
// exactly the same stream, stopping after at most signed size + 1 bytes. It
// neither opens paths nor closes the caller-owned reader. A blocking reader is
// controlled by its caller; this API adds no goroutines or background reads.
func VerifyArtifact(document []byte, publicKey ed25519.PublicKey, artifact io.Reader) (ArtifactIdentity, error) {
	verified, err := VerifyEnvelope(document, publicKey)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	if artifact == nil {
		return ArtifactIdentity{}, &Error{Kind: ErrRead}
	}
	expected := verified.Artifact
	hash := sha256.New()
	buffer := make([]byte, 32*1024)
	var count int64
	emptyReads := 0
	for {
		limit := min(int64(len(buffer)), expected.SizeBytes+1-count)
		n, readErr := artifact.Read(buffer[:limit])
		if n < 0 || int64(n) > limit {
			return ArtifactIdentity{}, &Error{Kind: ErrRead}
		}
		count += int64(n)
		if count > expected.SizeBytes {
			return ArtifactIdentity{}, &Error{Kind: ErrSize, ExpectedSize: expected.SizeBytes, ObservedSize: count}
		}
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			emptyReads = 0
		} else {
			emptyReads++
		}
		if readErr != nil {
			if readErr != io.EOF {
				return ArtifactIdentity{}, &Error{Kind: ErrRead, Cause: readErr}
			}
			break
		}
		if emptyReads >= 100 {
			return ArtifactIdentity{}, &Error{Kind: ErrRead, Cause: io.ErrNoProgress}
		}
	}
	if count != expected.SizeBytes {
		return ArtifactIdentity{}, &Error{Kind: ErrSize, ExpectedSize: expected.SizeBytes, ObservedSize: count}
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if digest != expected.SHA256 {
		return ArtifactIdentity{}, &Error{Kind: ErrDigest, ExpectedDigest: expected.SHA256, ObservedDigest: digest}
	}
	return ArtifactIdentity{SizeBytes: count, SHA256: digest}, nil
}
