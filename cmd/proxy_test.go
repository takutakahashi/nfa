package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListenControlUsesUnixSocketWhenConfigured(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "control.sock")

	lis, cleanup, err := listenControl(socketPath)
	if err != nil {
		t.Fatalf("listenControl(%q): %v", socketPath, err)
	}
	defer cleanup()
	defer lis.Close() //nolint:errcheck

	if got := lis.Addr().Network(); got != "unix" {
		t.Fatalf("listener network = %q, want unix", got)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("stat socket: %v", err)
	}
}

func TestListenControlRejectsExistingNonSocketPath(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "control.sock")
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	lis, cleanup, err := listenControl(socketPath)
	if err == nil {
		cleanup()
		_ = lis.Close()
		t.Fatal("listenControl() error = nil, want error")
	}
}
