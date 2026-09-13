package command_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance/packages/cli-go/internal/command"
)

func TestExistingArtifactRemainsBoundToLocalFileAndProject(t *testing.T) {
	for _, mode := range []string{"session", "project-token", "wrong-project", "wrong-digest", "wrong-size", "wrong-name", "pending", "wrong-id", "changed-file", "late-mutation", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cfg, jar := configFile(t, dir), filepath.Join(dir, "plugin.jar")
			content := []byte("already-verified-synthetic-jar")
			if err := os.WriteFile(jar, content, 0600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(content)
			candidates, snapshots, reads := 0, 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/artifacts/existing" && r.Method == "GET" {
					reads++
					body := map[string]any{"id": "existing", "projectId": "project", "sha256": hex.EncodeToString(digest[:]), "sizeBytes": len(content), "fileName": "plugin.jar", "state": "ready"}
					switch mode {
					case "wrong-project":
						body["projectId"] = "other"
					case "wrong-digest":
						body["sha256"] = strings.Repeat("0", 64)
					case "wrong-size":
						body["sizeBytes"] = len(content) + 1
					case "wrong-name":
						body["fileName"] = "other.jar"
					case "pending":
						body["state"] = "pending"
					case "wrong-id":
						body["id"] = "other"
					case "changed-file":
						_ = os.WriteFile(jar, []byte("changed-after-original-hash"), 0600)
					case "redirect":
						w.Header().Set("Location", "/unexpected")
						w.WriteHeader(307)
						return
					}
					reply(w, 200, body)
					return
				}
				if r.URL.Path == "/v1/projects/project/config-snapshots" && r.Method == "POST" {
					snapshots++
					if mode == "late-mutation" {
						_ = os.WriteFile(jar, []byte("changed-during-snapshot-creation"), 0600)
					}
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					reply(w, 201, map[string]any{"id": "snapshot", "projectId": "project", "configurationHash": body["configurationHash"], "sourceCommit": strings.Repeat("a", 40)})
					return
				}
				if r.URL.Path == "/v1/projects/project/release-candidates" && r.Method == "POST" {
					candidates++
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					if body["artifactId"] != "existing" || body["configurationSnapshotId"] != "snapshot" {
						t.Error("existing artifact binding changed")
					}
					reply(w, 201, map[string]any{"id": "candidate", "projectId": "project", "artifactId": "existing", "configurationHash": body["configurationHash"]})
					return
				}
				t.Error("unexpected request, upload, completion or redirect")
				w.WriteHeader(500)
			}))
			defer server.Close()
			var out, errs bytes.Buffer
			app := command.App{Out: &out, Err: &errs, Store: &store{values: map[string]string{server.URL + "/session": strings.Repeat("s", 43)}}, In: strings.NewReader(strings.Repeat("p", 43)), Transport: server.Client().Transport}
			args := []string{"test", "--origin", server.URL, "--timeout", "10s", "--project", "project", "--artifact", "existing", "--jar", jar, "--config", cfg, "--version", "1.0.1"}
			if mode == "project-token" || mode == "late-mutation" {
				args = append(args, "--auth", "project-token", "--project-token-stdin", "--source-commit", strings.Repeat("a", 40), "--source-ref", "refs/heads/main")
			} else {
				args = append(args, "--snapshot", "snapshot")
			}
			exit := app.Run(context.Background(), args)
			success := mode == "session" || mode == "project-token"
			if (exit == 0) != success || reads != 1 {
				t.Fatalf("exit=%d reads=%d error=%s", exit, reads, errs.String())
			}
			if !success && (candidates != 0 || (mode != "late-mutation" && snapshots != 0)) {
				t.Fatal("invalid existing artifact reached mutation")
			}
			if success && candidates != 1 {
				t.Fatal("candidate not created exactly once")
			}
		})
	}
}
