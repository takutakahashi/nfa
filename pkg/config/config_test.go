package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/takutakahashi/nfa/pkg/policy"
)

func TestFilePolicyStoreSaveCreatesConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nfa.yaml")
	store := NewFilePolicyStore(path)

	if err := store.Save(policy.Policy{
		Allowed:   []string{"example.com", "*.trusted.io"},
		CountMode: true,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Filter.Mode != "allowlist" {
		t.Fatalf("mode = %q, want allowlist", cfg.Filter.Mode)
	}
	if !cfg.Filter.CountMode {
		t.Fatal("countMode = false, want true")
	}
	want := []string{"example.com", "*.trusted.io"}
	if !reflect.DeepEqual(cfg.Filter.Domains, want) {
		t.Fatalf("domains = %v, want %v", cfg.Filter.Domains, want)
	}
}

func TestFilePolicyStoreSavePreservesDeferredPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nfa.yaml")
	initial := []byte("filter:\n  mode: allowlist\n  domains:\n    - old.example\ndeferredPolicy: true\n")
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewFilePolicyStore(path)
	if err := store.Save(policy.Policy{Denied: []string{"bad.example"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.DeferredPolicy {
		t.Fatal("deferredPolicy = false, want true")
	}
	if cfg.Filter.Mode != "denylist" {
		t.Fatalf("mode = %q, want denylist", cfg.Filter.Mode)
	}
	if !reflect.DeepEqual(cfg.Filter.Domains, []string{"bad.example"}) {
		t.Fatalf("domains = %v, want [bad.example]", cfg.Filter.Domains)
	}
}

func TestFilePolicyStoreSavePreservesControlSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nfa.yaml")
	initial := []byte("filter:\n  mode: allowlist\n  domains:\n    - old.example\ncontrolSocket: /tmp/nfa-control.sock\n")
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewFilePolicyStore(path)
	if err := store.Save(policy.Policy{Denied: []string{"bad.example"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ControlSocket != "/tmp/nfa-control.sock" {
		t.Fatalf("controlSocket = %q, want /tmp/nfa-control.sock", cfg.ControlSocket)
	}
	if cfg.Filter.Mode != "denylist" {
		t.Fatalf("mode = %q, want denylist", cfg.Filter.Mode)
	}
	if !reflect.DeepEqual(cfg.Filter.Domains, []string{"bad.example"}) {
		t.Fatalf("domains = %v, want [bad.example]", cfg.Filter.Domains)
	}
}

func TestFilePolicyStoreSavePreservesUpstreamProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nfa.yaml")
	initial := []byte("filter:\n  mode: allowlist\n  domains:\n    - old.example\nupstreamProxy: http://proxy.example:8080\n")
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewFilePolicyStore(path)
	if err := store.Save(policy.Policy{Denied: []string{"bad.example"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamProxy != "http://proxy.example:8080" {
		t.Fatalf("upstreamProxy = %q, want http://proxy.example:8080", cfg.UpstreamProxy)
	}
	if cfg.Filter.Mode != "denylist" {
		t.Fatalf("mode = %q, want denylist", cfg.Filter.Mode)
	}
}

func TestFilePolicyStoreSaveReadOnlyFileReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nfa.yaml")
	initial := []byte("filter:\n  mode: allowlist\n  domains:\n    - old.example\n")
	if err := os.WriteFile(path, initial, 0o444); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewFilePolicyStore(path)
	if err := store.Save(policy.Policy{Denied: []string{"bad.example"}}); err == nil {
		t.Fatal("Save error = nil, want error")
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.Filter.Domains, []string{"old.example"}) {
		t.Fatalf("domains = %v, want unchanged [old.example]", cfg.Filter.Domains)
	}
}

func TestFilePolicyStoreSaveReadOnlyDirectoryReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nfa.yaml")
	initial := []byte("filter:\n  mode: denylist\n  domains:\n    - old.example\n")
	if err := os.WriteFile(path, initial, 0o444); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("Chmod read-only: %v", err)
	}
	defer os.Chmod(dir, 0o755) //nolint:errcheck

	store := NewFilePolicyStore(path)
	if err := store.Save(policy.Policy{Denied: []string{"new.example"}}); err == nil {
		t.Fatal("Save error = nil, want error")
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.Filter.Domains, []string{"old.example"}) {
		t.Fatalf("domains = %v, want unchanged [old.example]", cfg.Filter.Domains)
	}
}
