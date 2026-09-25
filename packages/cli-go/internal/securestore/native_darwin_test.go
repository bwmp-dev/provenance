//go:build darwin && cgo

package securestore

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Requires CLI_NATIVE_KEYCHAIN to name a disposable keychain that the job has
// created, unlocked and made the default user keychain.
func TestNativeKeychain(t *testing.T) {
	nativeRoundtrip(t)
	keychain := os.Getenv("CLI_NATIVE_KEYCHAIN")
	if keychain == "" {
		t.Fatal("disposable keychain path required")
	}
	if e := exec.Command("security", "lock-keychain", keychain).Run(); e != nil {
		t.Fatal("lock disposable keychain", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := New().Ready(ctx); e == nil {
		t.Fatal("locked native store accepted")
	}
}
