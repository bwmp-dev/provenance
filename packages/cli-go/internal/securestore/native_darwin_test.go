//go:build darwin && cgo

package securestore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

// These tests run as separate processes against a disposable keychain that
// the CI job created, unlocked and made the default user keychain
// (CLI_NATIVE_KEYCHAIN). Items are stored with an empty trusted-application
// list (KeychainNotTrustApplication), so every secret read requires
// interactive user confirmation; a headless runner cannot grant it. The
// headless-checkable properties are therefore: the item is written to the
// Keychain, and an unconfirmed read fails closed within the caller's bound.

const keychainFixtureOrigin = "https://native-fixture.invalid"

func keychainFixture(t *testing.T) string {
	t.Helper()
	if os.Getenv("CLI_NATIVE_STORE_REQUIRED") != "1" {
		t.Skip("requires an explicit disposable keychain fixture")
	}
	keychain := os.Getenv("CLI_NATIVE_KEYCHAIN")
	if keychain == "" {
		t.Fatal("disposable keychain path required")
	}
	return keychain
}

// Step 1: the Keychain backend writes the session item. The job then checks
// the item's attributes (never its secret) with `security`.
func TestNativeKeychainStore(t *testing.T) {
	keychainFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := New()
	if e := s.open(); e != nil {
		t.Fatal("open Keychain backend", e)
	}
	if e := s.Set(ctx, keychainFixtureOrigin, "session", "synthetic-native-session-value"); e != nil {
		t.Fatal("Keychain write", e)
	}
}

// Step 2: without user confirmation, reads and the preflight never succeed
// silently and never fall back; they fail closed when the bound expires.
func TestNativeKeychainUnconfirmedReadFailsClosed(t *testing.T) {
	keychainFixture(t)
	s := New()
	if e := s.open(); e != nil {
		t.Fatal("open Keychain backend", e)
	}
	const bound = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	start := time.Now()
	if _, e := s.Get(ctx, keychainFixtureOrigin, "session"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unconfirmed Keychain read did not fail closed", e)
	}
	// An absent item fails immediately; a read awaiting confirmation runs to
	// the bound. The job has already proven the item exists.
	if elapsed := time.Since(start); elapsed < bound-500*time.Millisecond {
		t.Fatal("Keychain read ended before the bound; expected a confirmation wait", elapsed)
	}
	ready, stop := context.WithTimeout(context.Background(), bound)
	defer stop()
	if e := New().Ready(ready); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unconfirmed Keychain preflight accepted", e)
	}
}

// Step 3: a locked keychain is refused.
func TestNativeKeychainLocked(t *testing.T) {
	keychain := keychainFixture(t)
	if e := exec.Command("security", "lock-keychain", keychain).Run(); e != nil {
		t.Fatal("lock disposable keychain", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := New().Ready(ctx); !errors.Is(e, ErrUnavailable) {
		t.Fatal("locked native store accepted", e)
	}
}
