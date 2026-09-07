package command_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bwmp-dev/provenance/packages/cli-go/internal/command"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type store struct {
	values           map[string]string
	readyErr, setErr error
	sets             int
}

func (s *store) Ready(context.Context) error { return s.readyErr }
func (s *store) Get(_ context.Context, o, k string) (string, error) {
	v, ok := s.values[o+"/"+k]
	if !ok {
		return "", errors.New("absent")
	}
	return v, nil
}
func (s *store) Set(_ context.Context, o, k, v string) error {
	s.sets++
	if s.setErr != nil {
		return s.setErr
	}
	if s.values == nil {
		s.values = map[string]string{}
	}
	s.values[o+"/"+k] = v
	return nil
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func TestLoginReleasedFlowAndFailures(t *testing.T) {
	for _, mode := range []string{"success", "unavailable-store", "lost-session", "dropped-session-response", "consumed", "cancel", "write-failed", "expired", "bad-retry"} {
		t.Run(mode, func(t *testing.T) {
			var out, errs bytes.Buffer
			s := &store{}
			if mode == "unavailable-store" {
				s.readyErr = errors.New("secret-provider-details")
			}
			if mode == "write-failed" {
				s.setErr = errors.New("secret-provider-details")
			}
			requests, polls, redemptions, revokes := 0, 0, 0, 0
			expiry := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
			if mode == "expired" {
				expiry = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
			}
			var lastPoll time.Time
			device := strings.Repeat("A", 43)
			exchange := strings.Repeat("B", 42) + "A"
			credential := strings.Repeat("s", 43)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Header.Get("Origin") != "" || r.Header.Get("Authorization") != "" {
					t.Error("ambient authority")
				}
				switch r.URL.Path {
				case "/v1/auth/device-authorizations":
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					assertReleasedShape(t, "CreateDeviceAuthorizationRequest", body)
					lastPoll = time.Now()
					if r.Header.Get("Idempotency-Key") == "" {
						t.Error("missing initiation identity")
					}
					reply(w, 201, map[string]any{"deviceCode": device, "userCode": "ABCD-EFGH", "verificationUri": "https://confirm.invalid/verify", "expiresAt": expiry, "intervalSeconds": 1})
				case "/v1/auth/device-authorizations/exchanges":
					if time.Since(lastPoll) < 950*time.Millisecond {
						t.Error("poll interval ignored")
					}
					lastPoll = time.Now()
					polls++
					var b map[string]string
					_ = json.NewDecoder(r.Body).Decode(&b)
					if b["deviceCode"] != device {
						t.Error("wrong redemption authority")
					}
					if mode == "consumed" {
						reply(w, 409, map[string]any{"code": "device_authorization_consumed"})
						return
					}
					if polls == 1 {
						reply(w, 202, map[string]any{"state": "pending", "intervalSeconds": 1, "expiresAt": expiry})
						return
					}
					if polls == 2 {
						w.Header().Set("Retry-After", "1")
						if mode == "bad-retry" {
							w.Header().Set("Retry-After", "unbounded")
						}
						reply(w, 429, map[string]any{"code": "rate_limited"})
						return
					}
					reply(w, 200, map[string]any{"exchangeToken": exchange, "expiresAt": expiry})
				case "/v1/auth/sessions":
					redemptions++
					var b map[string]string
					_ = json.NewDecoder(r.Body).Decode(&b)
					assertReleasedShape(t, "CreateSessionRequest", b)
					if b["exchangeToken"] != exchange || r.Header.Get("Cookie") != "" {
						t.Error("exchange mismatch")
					}
					if mode == "lost-session" {
						reply(w, 503, map[string]any{"code": "unavailable"})
						return
					}
					if mode == "dropped-session-response" {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = conn.Close()
						return
					}
					http.SetCookie(w, &http.Cookie{Name: "provenance_session", Value: credential, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
					reply(w, 201, map[string]any{"id": "session", "userId": "owner", "state": "active", "createdAt": expiry, "expiresAt": expiry})
				case "/v1/auth/session":
					revokes++
					if r.Method != "DELETE" {
						t.Error("wrong compensation")
					}
					reply(w, 204, nil)
				default:
					t.Error("unexpected request")
				}
			}))
			defer server.Close()
			app := command.App{Out: &out, Err: &errs, Store: s, Transport: server.Client().Transport}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				time.AfterFunc(100*time.Millisecond, cancel)
			}
			exit := app.Run(ctx, []string{"auth", "login", "--origin", server.URL, "--timeout", "10s"})
			if (exit == 0) != (mode == "success") {
				t.Fatalf("unexpected exit %d %s", exit, errs.String())
			}
			if mode == "unavailable-store" && requests != 0 {
				t.Fatal("issued before secure storage")
			}
			if redemptions > 1 {
				t.Fatal("speculative credential retry")
			}
			if mode == "expired" && polls != 0 {
				t.Fatal("expired authorization polled")
			}
			if mode == "write-failed" && revokes != 1 {
				t.Fatal("missing failed-store compensation")
			}
			if mode == "success" && (s.sets != 1 || s.values[server.URL+"/session"] != credential) {
				t.Fatal("wrong store binding")
			}
			for _, secret := range []string{device, exchange, credential, "secret-provider-details"} {
				if strings.Contains(out.String()+errs.String(), secret) {
					t.Fatal("secret output")
				}
			}
		})
	}
}
func configFile(t *testing.T, dir string) string {
	t.Helper()
	b, e := os.ReadFile("../../../../schemas/fixtures/config/valid/self-hosted-unrestricted.yml")
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "provenance.yml")
	if os.WriteFile(p, b, 0600) != nil {
		t.Fatal("write fixture")
	}
	return p
}
func TestExactTestSubmissionAndUploadIsolation(t *testing.T) {
	const artifactID = "11111111-1111-4111-8111-111111111111"
	const snapshotID = "22222222-2222-4222-8222-222222222222"
	for _, mode := range []string{"session-snapshot", "project-token", "mutated", "redirect", "wrong-digest", "wrong-snapshot", "manual"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cfg := configFile(t, dir)
			jar := filepath.Join(dir, "plugin.jar")
			jarBytes := []byte("already-built-synthetic-jar")
			_ = os.WriteFile(jar, jarBytes, 0600)
			h := sha256.Sum256(jarBytes)
			digest := hex.EncodeToString(h[:])
			configurationHash := ""
			calls, candidates, creates := 0, 0, 0
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path == "/upload" {
					if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
						t.Error("platform credential sent to upload")
					}
					if mode == "redirect" {
						w.Header().Set("Location", server.URL+"/should-not-follow")
						w.WriteHeader(307)
						return
					}
					b, _ := io.ReadAll(r.Body)
					if mode != "mutated" && !bytes.Equal(b, jarBytes) {
						t.Error("different artifact bytes")
					}
					w.WriteHeader(200)
					return
				}
				switch r.URL.Path {
				case "/v1/projects/project/config-snapshots":
					creates++
					var b map[string]any
					_ = json.NewDecoder(r.Body).Decode(&b)
					assertReleasedShape(t, "CreateProjectConfigSnapshotRequest", b)
					configurationHash = b["configurationHash"].(string)
					if r.Header.Get("Authorization") == "" {
						t.Error("session created snapshot")
					}
					hash := configurationHash
					if mode == "wrong-snapshot" {
						hash = strings.Repeat("0", 64)
					}
					reply(w, 201, map[string]any{"id": snapshotID, "projectId": "project", "sourceCommit": strings.Repeat("a", 40), "configurationHash": hash})
				case "/v1/projects/project/artifacts/uploads":
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					assertReleasedShape(t, "CreateArtifactUploadRequest", body)
					if mode == "mutated" {
						_ = os.WriteFile(jar, []byte("changed-after-original-hash"), 0600)
					}
					reply(w, 201, map[string]any{"artifactId": artifactID, "uploadUrl": server.URL + "/upload", "expiresAt": time.Now().Add(time.Minute).UTC().Format(time.RFC3339), "requiredHeaders": map[string]string{"Content-Type": "application/java-archive"}})
				case "/v1/artifacts/" + artifactID + "/complete":
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					assertReleasedShape(t, "CompleteArtifactUploadRequest", body)
					sum := digest
					if mode == "wrong-digest" {
						sum = strings.Repeat("0", 64)
					}
					reply(w, 202, map[string]any{"id": artifactID, "projectId": "project", "sha256": sum, "sizeBytes": len(jarBytes), "state": "ready"})
				case "/v1/projects/project/release-candidates":
					candidates++
					var b map[string]any
					_ = json.NewDecoder(r.Body).Decode(&b)
					assertReleasedShape(t, "CreateReleaseCandidateRequest", b)
					if b["configurationSnapshotId"] != snapshotID || b["artifactId"] != artifactID {
						t.Error("identity binding")
					}
					reply(w, 201, map[string]any{"id": "candidate", "projectId": "project", "artifactId": artifactID, "configurationHash": b["configurationHash"]})
				default:
					t.Error("unexpected mutation or redirect")
				}
			}))
			defer server.Close()
			var out, errs bytes.Buffer
			s := &store{values: map[string]string{server.URL + "/session": strings.Repeat("s", 43)}}
			app := command.App{Out: &out, Err: &errs, Store: s, Transport: server.Client().Transport, In: strings.NewReader(strings.Repeat("p", 43) + "\n")}
			args := []string{"test", "--origin", server.URL, "--timeout", "10s", "--project", "project", "--jar", jar, "--config", cfg, "--version", "1.0.0"}
			if mode == "project-token" || mode == "wrong-snapshot" {
				args = append(args, "--auth", "project-token", "--project-token-stdin", "--source-commit", strings.Repeat("a", 40), "--source-ref", "refs/heads/main")
			} else {
				args = append(args, "--snapshot", snapshotID)
			}
			if mode == "manual" {
				b, _ := os.ReadFile("../../../../schemas/fixtures/config/valid/hosted.yml")
				_ = os.WriteFile(cfg, b, 0600)
			}
			exit := app.Run(context.Background(), args)
			success := mode == "session-snapshot" || mode == "project-token"
			if (exit == 0) != success {
				t.Fatalf("exit %d %s", exit, errs.String())
			}
			if !success && candidates != 0 {
				t.Fatal("invalid input reached candidate mutation")
			}
			if mode == "manual" && calls != 0 {
				t.Fatal("non-test-only mutation")
			}
			if mode == "session-snapshot" && creates != 0 {
				t.Fatal("session snapshot privilege bypass")
			}
		})
	}
}
func TestStatusPaginationAndOriginIsolation(t *testing.T) {
	pages := 0
	perPath := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "" {
			t.Error("missing session")
		}
		if strings.HasSuffix(r.URL.Path, "/candidate") {
			reply(w, 200, map[string]any{"id": "candidate", "state": "failed"})
			return
		}
		pages++
		perPath[r.URL.Path]++
		next := "opaque:/+?=& " + r.URL.Path
		want := ""
		if perPath[r.URL.Path] > 1 {
			want = next
		}
		assertReleasedPagination(t, r, want)
		more := perPath[r.URL.Path] == 1
		reply(w, 200, map[string]any{"items": []any{map[string]string{"id": "item", "state": "failed"}}, "page": map[string]any{"hasMore": more, "nextCursor": next}})
	}))
	defer server.Close()
	var out, errs bytes.Buffer
	s := &store{values: map[string]string{server.URL + "/session": strings.Repeat("s", 43)}}
	app := command.App{Out: &out, Err: &errs, Store: s, Transport: server.Client().Transport}
	if app.Run(context.Background(), []string{"status", "--origin", server.URL, "--timeout", "3s", "--candidate", "candidate"}) != 0 || pages != 4 {
		t.Fatalf("pagination %d %s", pages, errs.String())
	}
	if perPath["/v1/release-candidates/candidate/executions"] != 2 || perPath["/v1/release-candidates/candidate/events"] != 2 {
		t.Fatal("both released pagination endpoints must continue")
	}
	if app.Run(context.Background(), []string{"status", "--origin", "https://other.invalid", "--timeout", "3s", "--candidate", "candidate"}) == 0 {
		t.Fatal("cross-origin store adoption")
	}
}
func TestVerifyUsesAcceptedSmallArtifactVector(t *testing.T) {
	raw, e := os.ReadFile("../../../../schemas/fixtures/attestation/interop/small-artifact.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Document                  json.RawMessage
		ArtifactHex, PublicKeyHex string
	}
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("vector")
	}
	dir := t.TempDir()
	jar, att, key := filepath.Join(dir, "plugin.jar"), filepath.Join(dir, "attestation.json"), filepath.Join(dir, "trusted-key")
	artifact, e := hex.DecodeString(v.ArtifactHex)
	if e != nil {
		t.Fatal(e)
	}
	public, e := hex.DecodeString(v.PublicKeyHex)
	if e != nil {
		t.Fatal(e)
	}
	for path, b := range map[string][]byte{jar: artifact, att: v.Document, key: []byte(base64.RawURLEncoding.EncodeToString(public))} {
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("fixture write")
		}
	}
	var doc struct{ Signature struct{ KeyID string } }
	_ = json.Unmarshal(v.Document, &doc)
	binary := filepath.Join(dir, "provenance")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/provenance")
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("CLI build %v %s", e, out)
	}
	args := []string{"verify", "--jar", jar, "--attestation", att, "--public-key", key, "--key-id", doc.Signature.KeyID}
	if out, e := exec.Command(binary, args...).CombinedOutput(); e != nil {
		t.Fatalf("actual binary verification %v %s", e, out)
	}
	// Key retirement does not invalidate an explicitly trusted historical key;
	// there is no live active-key lookup or TOFU in this offline path.
	artifact[0] ^= 1
	_ = os.WriteFile(jar, artifact, 0600)
	if _, e := exec.Command(binary, args...).CombinedOutput(); e == nil {
		t.Fatal("tampered artifact accepted")
	}
	args[len(args)-1] = "different-key"
	if _, e := exec.Command(binary, args...).CombinedOutput(); e == nil {
		t.Fatal("key identity mismatch accepted")
	}
}
