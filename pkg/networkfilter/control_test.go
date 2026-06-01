package networkfilter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
)

func newControlHandler(proxy *Proxy) http.Handler {
	cs := NewControlServer(proxy)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enable-policy", func(w http.ResponseWriter, r *http.Request) {
		cs.proxy.EnablePolicy()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /domains", func(w http.ResponseWriter, _ *http.Request) {
		f := cs.proxy.configuredFilter
		mode := "denylist"
		if f.IsAllowlistMode() {
			mode = "allowlist"
		}
		resp := domainsResponse{
			Mode:    mode,
			Allowed: f.AllowedDomains(),
			Denied:  f.DeniedDomains(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

func TestControlDomainsAllowlistMode(t *testing.T) {
	want := []string{"example.com", "*.trusted.io"}
	proxy := NewProxy(NewAllowlistFilter(want), true)
	handler := newControlHandler(proxy)

	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body domainsResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Mode != "allowlist" {
		t.Errorf("mode = %q, want allowlist", body.Mode)
	}
	got := body.Allowed
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed = %v, want %v", got, want)
	}
	if len(body.Denied) != 0 {
		t.Errorf("denied = %v, want empty in allowlist mode", body.Denied)
	}
}

func TestControlDomainsDenylistMode(t *testing.T) {
	want := []string{"bad.com", "*.evil.org"}
	proxy := NewProxy(NewFilter(want), true)
	handler := newControlHandler(proxy)

	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var body domainsResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Mode != "denylist" {
		t.Errorf("mode = %q, want denylist", body.Mode)
	}
	got := body.Denied
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("denied = %v, want %v", got, want)
	}
	if len(body.Allowed) != 0 {
		t.Errorf("allowed = %v, want empty in denylist mode", body.Allowed)
	}
}

func TestControlDomainsEmptyLists(t *testing.T) {
	proxy := NewProxy(NewFilter(nil), true)
	handler := newControlHandler(proxy)

	req := httptest.NewRequest(http.MethodGet, "/domains", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body domainsResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Allowed == nil {
		t.Error("allowed is null, want empty array")
	}
	if body.Denied == nil {
		t.Error("denied is null, want empty array")
	}
}
