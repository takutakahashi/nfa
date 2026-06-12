package networkfilter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/takutakahashi/nfa/pkg/config"
)

func TestControlPolicyHTTPPersistsToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nfa.yaml")
	initial := []byte("filter:\n  mode: allowlist\n  domains:\n    - old.example\ndeferredPolicy: true\n")
	if err := os.WriteFile(path, initial, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	proxy := NewProxy(NewAllowlistFilter([]string{"old.example"}), true)
	handler := NewControlServer(proxy, config.NewFilePolicyStore(path)).Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	body := bytes.NewBufferString(`{"denied":["bad.example"],"count_mode":true}`)
	resp, err := http.Post(server.URL+"/policy", "application/json", body)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Filter.Mode != "denylist" {
		t.Fatalf("mode = %q, want denylist", cfg.Filter.Mode)
	}
	if !cfg.Filter.CountMode {
		t.Fatal("countMode = false, want true")
	}
	if !reflect.DeepEqual(cfg.Filter.Domains, []string{"bad.example"}) {
		t.Fatalf("domains = %v, want [bad.example]", cfg.Filter.Domains)
	}
	if !cfg.DeferredPolicy {
		t.Fatal("deferredPolicy = false, want true")
	}

	filter := proxy.effectiveFilter()
	if got := filter.Check("bad.example"); got != FilterResultBlocked {
		t.Fatalf("Check(bad.example) = %s, want blocked", got)
	}
}

func TestControlPolicyHTTPReadOnlyStoreReturnsErrorAndKeepsPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nfa.yaml")
	initial := []byte("filter:\n  mode: denylist\n  domains:\n    - old.example\n")
	if err := os.WriteFile(path, initial, 0o444); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	proxy := NewProxy(NewFilter([]string{"old.example"}), true)
	handler := NewControlServer(proxy, config.NewFilePolicyStore(path)).Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	body := bytes.NewBufferString(`{"denied":["new.example"]}`)
	resp, err := http.Post(server.URL+"/policy", "application/json", body)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(cfg.Filter.Domains, []string{"old.example"}) {
		t.Fatalf("domains = %v, want unchanged [old.example]", cfg.Filter.Domains)
	}

	filter := proxy.effectiveFilter()
	if got := filter.Check("new.example"); got != FilterResultAllowed {
		t.Fatalf("Check(new.example) = %s, want allowed", got)
	}
	if got := filter.Check("old.example"); got != FilterResultBlocked {
		t.Fatalf("Check(old.example) = %s, want blocked", got)
	}

	var domains domainsResponse
	getResp, err := http.Get(server.URL + "/domains")
	if err != nil {
		t.Fatalf("Get /domains: %v", err)
	}
	defer getResp.Body.Close() //nolint:errcheck
	if err := json.NewDecoder(getResp.Body).Decode(&domains); err != nil {
		t.Fatalf("decode /domains: %v", err)
	}
}
