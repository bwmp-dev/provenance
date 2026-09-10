package verification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestSharedV2GoldenVector(t *testing.T) {
	var vector struct {
		Document                                                                                                        json.RawMessage
		ArtifactHex, PublicKeyHex, CanonicalStatement, CanonicalStatementSha256, SigningInputSha256, SignatureBase64Url string
	}
	if err := json.Unmarshal(readFixture(t, "interop/small-artifact-v2.json"), &vector); err != nil {
		t.Fatal(err)
	}
	public := ed25519.PublicKey(decodeHex(t, vector.PublicKeyHex))
	if _, err := VerifyArtifact(vector.Document, public, bytes.NewReader(decodeHex(t, vector.ArtifactHex))); err != nil {
		t.Fatal(err)
	}
	doc := object(t, vector.Document)
	canonical, err := canonicalJSON(doc["statement"])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	if string(canonical) != vector.CanonicalStatement || hex.EncodeToString(digest[:]) != vector.CanonicalStatementSha256 {
		t.Fatal("shared v2 canonical bytes differ")
	}
	sig := doc["signature"].(map[string]any)
	input := append([]byte("Provenance Attestation v2\n"+sig["keyId"].(string)+"\n"), canonical...)
	digest = sha256.Sum256(input)
	if hex.EncodeToString(digest[:]) != vector.SigningInputSha256 {
		t.Fatal("shared v2 signing input differs")
	}
	var seed struct{ PrivateKeySeedHex string }
	if err := json.Unmarshal(readFixture(t, "vectors/hosted.json"), &seed); err != nil {
		t.Fatal(err)
	}
	reproduced := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(decodeHex(t, seed.PrivateKeySeedHex)), input))
	if reproduced != vector.SignatureBase64Url || reproduced != sig["value"] {
		t.Fatal("shared v2 signature differs")
	}
}

func signedV2(t *testing.T, literal bool, domain string) ([]byte, []byte, ed25519.PublicKey) {
	t.Helper()
	v, artifact, key := small(t)
	doc := object(t, v.Document)
	doc["mediaType"] = "application/vnd.provenance.attestation.v2+json"
	statement := doc["statement"].(map[string]any)
	statement["apiVersion"] = "provenance.dev/attestation/v2"
	if literal {
		assertion := statement["assertions"].([]any)[0].(map[string]any)
		assertion["type"] = "console-contains"
		assertion["id"] = "console-contains:smoke:0"
	}
	var vector struct{ PrivateKeySeedHex string }
	if err := json.Unmarshal(readFixture(t, "vectors/hosted.json"), &vector); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(statement)
	if err != nil {
		t.Fatal(err)
	}
	signature := doc["signature"].(map[string]any)
	input := append([]byte(domain+signature["keyId"].(string)+"\n"), canonical...)
	signature["value"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(decodeHex(t, vector.PrivateKeySeedHex)), input))
	return marshal(t, doc), artifact, key
}

func TestV2LiteralArtifactAndDomainSeparation(t *testing.T) {
	raw, artifact, key := signedV2(t, true, "Provenance Attestation v2\n")
	if _, err := VerifyArtifact(raw, key, bytes.NewReader(artifact)); err != nil {
		t.Fatal(err)
	}
	wrong, _, _ := signedV2(t, true, "Provenance Attestation v1\n")
	if _, err := VerifyEnvelope(wrong, key); !errors.Is(err, ErrSignature) {
		t.Fatal("v1 signing domain accepted as v2", err)
	}
	// Even overlapping assertion types cannot be relabelled into v1.
	overlap, _, _ := signedV2(t, false, "Provenance Attestation v2\n")
	doc := object(t, overlap)
	doc["mediaType"] = "application/vnd.provenance.attestation.v1+json"
	doc["statement"].(map[string]any)["apiVersion"] = "provenance.dev/attestation/v1"
	if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSignature) {
		t.Fatal("v2 signature accepted after v1 relabel", err)
	}
	for _, path := range [][]any{{"mediaType"}, {"statement", "apiVersion"}} {
		doc := object(t, raw)
		value := "provenance.dev/attestation/v1"
		if len(path) == 1 {
			value = "application/vnd.provenance.attestation.v1+json"
		}
		setPath(t, doc, path, value)
		if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSchema) {
			t.Fatal("mixed envelope admitted", err)
		}
	}
}

func TestV2SchemaCopyAndLiteralBoundaries(t *testing.T) {
	authority, err := os.ReadFile("../../schemas/attestation/v2/schema.json")
	if err != nil || !bytes.Equal(authority, schemaV2Bytes) {
		t.Fatal("v2 schema differs from authority", err)
	}
	raw, _, key := signedV2(t, true, "Provenance Attestation v2\n")
	for _, id := range []string{"literal\n", "literal/unsafe", string(bytes.Repeat([]byte("a"), 129))} {
		doc := object(t, raw)
		setPath(t, doc, []any{"statement", "assertions", float64(0), "id"}, id)
		if _, err := VerifyEnvelope(marshal(t, doc), key); !errors.Is(err, ErrSchema) {
			t.Fatal("invalid assertion ID admitted", err)
		}
	}
}
