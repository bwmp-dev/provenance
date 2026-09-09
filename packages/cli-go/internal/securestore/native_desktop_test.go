//go:build darwin || windows

package securestore

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestNativeDesktopCredentialStore(t *testing.T) {
	if os.Getenv("CLI_NATIVE_STORE_REQUIRED") != "1" {
		t.Skip("requires an explicit disposable native desktop runner")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Fatalf("native desktop acceptance ran on %s", runtime.GOOS)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store := New()
	if err := store.Ready(ctx); err != nil {
		t.Fatal("native preflight", err)
	}

	origin := "https://native-desktop-fixture.invalid"
	kind := "session"
	key := origin + "/" + kind
	defer func() {
		if store.ring != nil {
			_ = store.ring.Remove(key)
		}
	}()
	value := "synthetic-native-desktop-session-value"
	if err := store.Set(ctx, origin, kind, value); err != nil {
		t.Fatal("native set", err)
	}
	got, err := store.Get(ctx, origin, kind)
	if err != nil || got != value {
		t.Fatal("native roundtrip", err)
	}
	if _, err = store.Get(ctx, "https://foreign.invalid", kind); err == nil {
		t.Fatal("origin isolation")
	}
	if _, err = store.Get(ctx, origin, "project-token"); err == nil {
		t.Fatal("credential kind isolation")
	}
	if err = store.ring.Remove(key); err != nil {
		t.Fatal("native remove", err)
	}
	if _, err = store.Get(ctx, origin, kind); err == nil {
		t.Fatal("removed credential remained readable")
	}
}
