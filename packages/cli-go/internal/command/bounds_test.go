package command_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bwmp-dev/provenance/packages/cli-go/internal/command"
)

func TestExplicitOriginAndBoundedCredentialInput(t *testing.T) {
	for _, base := range []string{"", "http://api.invalid", "https://user:password@api.invalid", "https://api.invalid/path", "https://api.invalid?token=secret", "https://api.invalid#fragment"} {
		var out, errs bytes.Buffer
		a := command.App{Out: &out, Err: &errs, Store: &store{}}
		if a.Run(context.Background(), []string{"auth", "login", "--origin", base, "--timeout", "1s"}) == 0 {
			t.Fatal("unsafe origin accepted")
		}
		if strings.Contains(errs.String(), "password") || strings.Contains(errs.String(), "secret") {
			t.Fatal("input reflected")
		}
	}
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	var out, errs bytes.Buffer
	a := command.App{Out: &out, Err: &errs, In: input}
	start := time.Now()
	if a.Run(context.Background(), []string{"status", "--origin", "https://api.invalid", "--timeout", "20ms", "--candidate", "candidate", "--auth", "project-token", "--project-token-stdin"}) == 0 || time.Since(start) > time.Second {
		t.Fatal("stdin not deadline bounded")
	}
}

func TestStatusRejectsOversizeAndCursorCycles(t *testing.T) {
	for _, mode := range []string{"oversize", "duplicate", "cycle"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "oversize" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"id":"`+strings.Repeat("x", 4*1024*1024)+`"}`)
					return
				}
				if mode == "duplicate" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"id":"candidate","id":"other","state":"failed"}`)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/candidate") {
					reply(w, 200, map[string]any{"id": "candidate", "state": "failed"})
					return
				}
				want := ""
				if calls > 2 {
					want = "same"
				}
				assertReleasedPagination(t, r, want)
				reply(w, 200, map[string]any{"items": []any{}, "page": map[string]any{"hasMore": true, "nextCursor": "same"}})
			}))
			defer s.Close()
			var out, errs bytes.Buffer
			a := command.App{Out: &out, Err: &errs, Store: &store{values: map[string]string{s.URL + "/session": strings.Repeat("s", 43)}}, Transport: s.Client().Transport}
			if a.Run(context.Background(), []string{"status", "--origin", s.URL, "--timeout", "3s", "--candidate", "candidate"}) == 0 {
				t.Fatal("unbounded response accepted")
			}
			if mode == "cycle" && calls != 3 {
				t.Fatalf("cursor cycle not bounded: %d", calls)
			}
		})
	}
}
