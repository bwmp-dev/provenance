package command_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bwmp-dev/provenance/packages/cli-go/internal/command"
)

func TestStatusExplicitGatewayRouting(t *testing.T) {
	for _, auth := range []string{"session", "project-token"} {
		t.Run(auth, func(t *testing.T) {
			calls := map[string]int{}
			credential := strings.Repeat("s", 43)
			handler := func(role string) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					if (auth == "session" && r.Header.Get("Cookie") != "provenance_session="+credential) ||
						(auth == "project-token" && r.Header.Get("Authorization") != "Bearer "+credential) {
						t.Error("selected credential was not sent to its configured destination")
					}
					calls[role]++
					isExecution := strings.HasSuffix(r.URL.Path, "/executions")
					if isExecution != (role == "gateway") {
						t.Errorf("%s received wrong route %s", role, r.URL.Path)
						http.NotFound(w, r)
						return
					}
					if strings.HasSuffix(r.URL.Path, "/candidate") {
						reply(w, 200, map[string]any{"id": "candidate", "state": "passed"})
						return
					}
					reply(w, 200, map[string]any{"items": []any{}, "page": map[string]any{"hasMore": false}})
				}
			}
			api := httptest.NewTLSServer(handler("api"))
			defer api.Close()
			gateway := httptest.NewTLSServer(handler("gateway"))
			defer gateway.Close()
			var out, errs bytes.Buffer
			s := &store{values: map[string]string{api.URL + "/" + auth: credential}}
			app := command.App{Out: &out, Err: &errs, Store: s, Transport: api.Client().Transport}
			args := []string{"status", "--origin", api.URL, "--gateway-origin", gateway.URL, "--auth", auth, "--timeout", "3s", "--candidate", "candidate"}
			if app.Run(context.Background(), args) != 0 || calls["api"] != 2 || calls["gateway"] != 1 {
				t.Fatalf("routing %v: %s", calls, errs.String())
			}
			for _, invalid := range []string{"http://gateway.invalid", "https://user:secret@gateway.invalid", "https://gateway.invalid/path"} {
				args[4] = invalid
				if app.Run(context.Background(), args) == 0 || calls["api"] != 2 || calls["gateway"] != 1 {
					t.Fatal("invalid gateway reached the network")
				}
			}
		})
	}
}
