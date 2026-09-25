//go:build darwin && !cgo

package securestore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Release binaries are cross-compiled with CGO disabled, which removes the
// Keychain backend. The store must then fail closed, never fall back.
func TestKeychainUnavailableWithoutCgo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := New()
	if e := s.Ready(ctx); !errors.Is(e, ErrUnavailable) {
		t.Fatal("CGO-disabled darwin store did not fail closed", e)
	}
	if e := s.Set(ctx, "https://native-fixture.invalid", "session", "value"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("CGO-disabled darwin store accepted a credential", e)
	}
}
