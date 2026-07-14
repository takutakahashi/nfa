package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadSetupDirectAllowlist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("filter:\n  mode: allowlist\n  domains:\n    - 192.0.2.10\n    - 198.51.100.0/24\n    - example.com\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadSetupDirectAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.10", "198.51.100.0/24", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadSetupDirectAllowlist() = %v, want %v", got, want)
	}
}

func TestLoadSetupDirectAllowlistIgnoresDenylist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("filter:\n  mode: denylist\n  domains:\n    - 192.0.2.10\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := loadSetupDirectAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("loadSetupDirectAllowlist() = %v, want nil", got)
	}
}
