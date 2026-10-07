package command_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance/packages/cli-go/internal/command"
)

type verifyVector struct {
	Document                  json.RawMessage
	ArtifactHex, PublicKeyHex string
}

type verifyInputs struct {
	jar, attestation, key, keyID string
	artifact, document           []byte
	public                       []byte
}

func loadVerifyVector(t *testing.T, path string) verifyInputs {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var v verifyVector
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("vector")
	}
	artifact, e := hex.DecodeString(v.ArtifactHex)
	if e != nil {
		t.Fatal(e)
	}
	public, e := hex.DecodeString(v.PublicKeyHex)
	if e != nil {
		t.Fatal(e)
	}
	var doc struct{ Signature struct{ KeyID string } }
	if json.Unmarshal(v.Document, &doc) != nil || doc.Signature.KeyID == "" {
		t.Fatal("vector keyId")
	}
	dir := t.TempDir()
	in := verifyInputs{
		jar: filepath.Join(dir, "plugin.jar"), attestation: filepath.Join(dir, "attestation.json"), key: filepath.Join(dir, "trusted-key"),
		keyID: doc.Signature.KeyID, artifact: artifact, document: v.Document, public: public,
	}
	in.write(t)
	return in
}

func (in verifyInputs) write(t *testing.T) {
	t.Helper()
	for path, b := range map[string][]byte{in.jar: in.artifact, in.attestation: in.document, in.key: []byte(base64.RawURLEncoding.EncodeToString(in.public))} {
		if os.WriteFile(path, b, 0o600) != nil {
			t.Fatal("fixture write")
		}
	}
}

func runVerify(in verifyInputs, keyID string) (int, string, string) {
	var out, errs bytes.Buffer
	app := command.App{Out: &out, Err: &errs}
	code := app.Run(context.Background(), []string{"verify", "--jar", in.jar, "--attestation", in.attestation, "--public-key", in.key, "--key-id", keyID})
	return code, out.String(), errs.String()
}

func expectVerifyFailure(t *testing.T, in verifyInputs, keyID, reason string) {
	t.Helper()
	code, out, errs := runVerify(in, keyID)
	if code == 0 || out != "" {
		t.Fatalf("accepted: %d %q", code, out)
	}
	if !strings.Contains(errs, "verification failed: "+reason) {
		t.Fatalf("want reason %q, got %q", reason, errs)
	}
}

// A hosted-runner-shaped v2 envelope (as production issues since the v2
// rollout): multi-environment, gVisor sandbox and a v2 configuration.
func TestVerifyHostedV2Envelope(t *testing.T) {
	in := loadVerifyVector(t, "testdata/hosted-v2.json")
	code, out, errs := runVerify(in, in.keyID)
	if code != 0 {
		t.Fatalf("v2 rejected: %s", errs)
	}
	var got struct {
		SizeBytes int64
		SHA256    string
	}
	if json.Unmarshal([]byte(out), &got) != nil || got.SizeBytes != int64(len(in.artifact)) || len(got.SHA256) != 64 {
		t.Fatalf("unexpected output %q", out)
	}

	t.Run("appended byte", func(t *testing.T) {
		tampered := in
		tampered.artifact = append(bytes.Clone(in.artifact), 0)
		tampered.write(t)
		defer in.write(t)
		expectVerifyFailure(t, tampered, in.keyID, "artifact size does not match the attestation")
	})
	t.Run("flipped byte", func(t *testing.T) {
		tampered := in
		tampered.artifact = bytes.Clone(in.artifact)
		tampered.artifact[len(tampered.artifact)/2] ^= 1
		tampered.write(t)
		defer in.write(t)
		expectVerifyFailure(t, tampered, in.keyID, "artifact SHA-256 does not match the attestation")
	})
	t.Run("wrong key id flag", func(t *testing.T) {
		expectVerifyFailure(t, in, "provenance-other-issuer", "attestation keyId does not match --key-id")
	})
	t.Run("substituted key id in document", func(t *testing.T) {
		// The signing input binds keyId, so renaming the key in the envelope
		// (and asking for that name) must fail the signature.
		swapped := in
		swapped.document = bytes.Replace(in.document, []byte(`"`+in.keyID+`"`), []byte(`"provenance-other-issuer"`), 1)
		swapped.write(t)
		defer in.write(t)
		expectVerifyFailure(t, swapped, "provenance-other-issuer", "attestation signature is not valid for the trusted public key")
	})
	t.Run("different trusted key", func(t *testing.T) {
		other := in
		other.public = bytes.Clone(in.public)
		other.public[0] ^= 1
		other.write(t)
		defer in.write(t)
		code, _, _ := runVerify(other, in.keyID)
		if code == 0 {
			t.Fatal("different key accepted")
		}
	})
	t.Run("unsupported envelope version", func(t *testing.T) {
		future := in
		future.document = bytes.Replace(in.document, []byte("attestation.v2+json"), []byte("attestation.v3+json"), 1)
		future.write(t)
		defer in.write(t)
		expectVerifyFailure(t, future, in.keyID, "unsupported attestation envelope version")
	})
	t.Run("schema violation", func(t *testing.T) {
		broken := in
		broken.document = bytes.Replace(in.document, []byte(`"provenance.dev/attestation/v2"`), []byte(`"provenance.dev/attestation/v1"`), 1)
		broken.write(t)
		defer in.write(t)
		expectVerifyFailure(t, broken, in.keyID, "attestation does not match")
	})
}

// v1 envelopes remain accepted alongside v2.
func TestVerifyKeepsV1Envelope(t *testing.T) {
	in := loadVerifyVector(t, "../../../../schemas/fixtures/attestation/interop/small-artifact.json")
	if code, _, errs := runVerify(in, in.keyID); code != 0 {
		t.Fatalf("v1 rejected: %s", errs)
	}
	in.artifact = append(in.artifact, 0)
	in.write(t)
	expectVerifyFailure(t, in, in.keyID, "artifact size does not match the attestation")
}
