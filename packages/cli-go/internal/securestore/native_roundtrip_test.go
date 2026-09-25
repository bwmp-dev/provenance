//go:build (darwin && cgo) || windows

package securestore

import (
	"context"
	"os"
	"testing"
	"time"
)

// nativeRoundtrip exercises the real OS credential store through the same
// Ready/Set/Get path as the CLI, then removes its synthetic item. It is opt-in
// so ordinary test runs never touch a developer's credential store.
func nativeRoundtrip(t *testing.T) {
	t.Helper()
	if os.Getenv("CLI_NATIVE_STORE_REQUIRED") != "1" {
		t.Skip("requires an explicit disposable native credential store fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s := New()
	if e := s.Ready(ctx); e != nil {
		t.Fatal("native preflight", e)
	}
	origin := "https://native-fixture.invalid"
	key := origin + "/session"
	defer s.ring.Remove(key)
	value := "synthetic-native-session-value"
	if e := s.Set(ctx, origin, "session", value); e != nil {
		t.Fatal(e)
	}
	got, e := s.Get(ctx, origin, "session")
	if e != nil || got != value {
		t.Fatal("native roundtrip", e)
	}
	if _, e = s.Get(ctx, "https://foreign.invalid", "session"); e == nil {
		t.Fatal("origin isolation")
	}
	if _, e = s.Get(ctx, origin, "project-token"); e == nil {
		t.Fatal("credential kind isolation")
	}
	if e = s.ring.Remove(key); e != nil {
		t.Fatal("native remove", e)
	}
	if _, e = s.Get(ctx, origin, "session"); e == nil {
		t.Fatal("removed credential still readable")
	}
}
