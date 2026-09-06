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
	"runtime"
	"testing"
)

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func signedArtifact(t *testing.T, size int64, digest string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	v, _, key := small(t)
	doc := object(t, v.Document)
	subject := doc["statement"].(map[string]any)["subject"].(map[string]any)
	subject["sizeBytes"] = float64(size)
	subject["digest"].(map[string]any)["value"] = digest
	var vector struct{ PrivateKeySeedHex string }
	if err := json.Unmarshal(readFixture(t, "vectors/hosted.json"), &vector); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(doc["statement"])
	if err != nil {
		t.Fatal(err)
	}
	keyID := doc["signature"].(map[string]any)["keyId"].(string)
	input := append([]byte("Provenance Attestation v1\n"+keyID+"\n"), canonical...)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(decodeHex(t, vector.PrivateKeySeedHex)), input)
	doc["signature"].(map[string]any)["value"] = base64.RawURLEncoding.EncodeToString(sig)
	return marshal(t, doc), key
}
func TestLargeStreamUsesBoundedMemory(t *testing.T) {
	const size = 128 << 20
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(zeros{}, size)); err != nil {
		t.Fatal(err)
	}
	raw, key := signedArtifact(t, size, hex.EncodeToString(hash.Sum(nil)))
	// Warm schema compilation before measuring artifact-stream allocation.
	if _, err := VerifyEnvelope(raw, key); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result, err := VerifyArtifact(raw, key, io.LimitReader(zeros{}, size))
	runtime.ReadMemStats(&after)
	if err != nil || result.SizeBytes != size {
		t.Fatalf("%+v %v", result, err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Fatalf("stream allocated %d bytes", allocated)
	}
}
func TestReaderDataAndErrorAreBothObserved(t *testing.T) {
	v, artifact, key := small(t)
	for _, end := range []error{io.EOF, errors.New("hostile-marker"), errors.Join(io.EOF, errors.New("hostile-marker"))} {
		reads := 0
		result, err := VerifyArtifact(v.Document, key, readerFunc(func(p []byte) (int, error) { reads++; n := copy(p, artifact); return n, end }))
		if end == io.EOF {
			if err != nil || result.SizeBytes != int64(len(artifact)) {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrRead) || !errors.Is(err, end) {
			t.Fatalf("lost read error %v", err)
		}
		if reads != 1 {
			t.Fatalf("continued after error: %d", reads)
		}
	}
}
func TestSignedWrongSizeAndDigest(t *testing.T) {
	v, artifact, _ := small(t)
	var doc map[string]any
	if err := json.Unmarshal(v.Document, &doc); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		size   int64
		digest string
		want   error
	}{
		{int64(len(artifact) - 1), doc["statement"].(map[string]any)["subject"].(map[string]any)["digest"].(map[string]any)["value"].(string), ErrSize},
		{int64(len(artifact)), hex.EncodeToString(make([]byte, 32)), ErrDigest},
	} {
		raw, key := signedArtifact(t, test.size, test.digest)
		if _, err := VerifyArtifact(raw, key, bytes.NewReader(artifact)); !errors.Is(err, test.want) {
			t.Fatalf("want %v got %v", test.want, err)
		}
	}
}
