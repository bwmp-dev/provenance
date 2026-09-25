//go:build windows

package securestore

import "testing"

// Uses the job user's Windows Credential Manager; the synthetic item is removed.
func TestNativeCredentialManager(t *testing.T) {
	nativeRoundtrip(t)
}
