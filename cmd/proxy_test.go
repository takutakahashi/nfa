package cmd

import (
	"errors"
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

func TestProxyCommandHasWithSetupFlag(t *testing.T) {
	flag := proxyCmd.Flags().Lookup("with-setup")
	if flag == nil {
		t.Fatal("proxy --with-setup flag is not registered")
	}
}

func TestMaybeSetupIPTablesSkipsWhenDisabled(t *testing.T) {
	oldSetup := setupIPTables
	defer func() { setupIPTables = oldSetup }()

	called := false
	setupIPTables = func() error {
		called = true
		return nil
	}

	if err := maybeSetupIPTables(false); err != nil {
		t.Fatalf("maybeSetupIPTables(false): %v", err)
	}
	if called {
		t.Fatal("setupIPTables called when withSetup=false")
	}
}

func TestMaybeSetupIPTablesRunsWhenEnabled(t *testing.T) {
	oldSetup := setupIPTables
	defer func() { setupIPTables = oldSetup }()

	called := false
	setupIPTables = func() error {
		called = true
		return nil
	}

	if err := maybeSetupIPTables(true); err != nil {
		t.Fatalf("maybeSetupIPTables(true): %v", err)
	}
	if !called {
		t.Fatal("setupIPTables was not called")
	}
}

func TestMaybeSetupIPTablesReturnsSetupError(t *testing.T) {
	oldSetup := setupIPTables
	defer func() { setupIPTables = oldSetup }()

	setupIPTables = func() error {
		return errors.New("net admin missing")
	}

	if err := maybeSetupIPTables(true); err == nil {
		t.Fatal("maybeSetupIPTables(true) error = nil, want error")
	}
}
