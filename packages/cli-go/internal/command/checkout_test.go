package command_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCleanSourceCheckoutBuild(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	clean := t.TempDir()
	for _, name := range []string{"cli-go", "verification-go"} {
		target := filepath.Join(clean, "packages", name)
		if err = os.MkdirAll(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.CopyFS(target, os.DirFS(filepath.Join(root, "packages", name))); err != nil {
			t.Fatal(err)
		}
	}
	// No ambient go.work: the explicit sibling binding must suffice. This is a
	// complete source-checkout build, not a claim of a published nested module.
	cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(clean, "provenance"), "./cmd/provenance")
	cmd.Dir = filepath.Join(clean, "packages", "cli-go")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clean checkout build: %v: %s", err, out)
	}
}
