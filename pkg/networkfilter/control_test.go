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
	mux.HandleFunc("GET /domains/allowed", func(w http.ResponseWriter, _ *http.Request) {
		domains := cs.proxy.configuredFilter.AllowedDomains()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"domains": domains})
	})
	mux.HandleFunc("GET /domains/denied", func(w http.ResponseWriter, _ *http.Request) {
		domains := cs.proxy.configuredFilter.DeniedDomains()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"domains": domains})
	})
	return mux
}

func TestControlDomainsAllowed(t *testing.T) {
	want := []string{"example.com", "*.trusted.io"}
	proxy := NewProxy(NewAllowlistFilter(want), true)
	handler := newControlHandler(proxy)

	req := httptest.NewRequest(http.MethodGet, "/domains/allowed", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string][]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := body["domains"]
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("allowed domains = %v, want %v", got, want)
	}
}

func TestControlDomainsAllowedEmptyInDenylistMode(t *testing.T) {
	proxy := NewProxy(NewFilter([]string{"bad.com"}), true)
	handler := newControlHandler(proxy)

	req := httptest.NewRequest(http.MethodGet, "/domains/allowed", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string][]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body["domains"]; len(got) != 0 {
		t.Errorf("allowed domains = %v, want empty in denylist mode", got)
	}
}

func TestControlDomainsDenied(t *testing.T) {
	want := []string{"bad.com", "*.evil.org"}
	proxy := NewProxy(NewFilter(want), true)
	handler := newControlHandler(proxy)

	req := httptest.NewRequest(http.MethodGet, "/domains/denied", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string][]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := body["domains"]
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("denied domains = %v, want %v", got, want)
	}
}

func TestControlDomainsDeniedEmptyInAllowlistMode(t *testing.T) {
	proxy := NewProxy(NewAllowlistFilter([]string{"example.com"}), true)
	handler := newControlHandler(proxy)

	req := httptest.NewRequest(http.MethodGet, "/domains/denied", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body map[string][]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := body["domains"]; len(got) != 0 {
		t.Errorf("denied domains = %v, want empty in allowlist mode", got)
	}
}

func TestControlDomainsEmptyLists(t *testing.T) {
	proxy := NewProxy(NewFilter(nil), true)
	handler := newControlHandler(proxy)

	for _, path := range []string{"/domains/allowed", "/domains/denied"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, w.Code)
		}
		var body map[string][]string
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
		if body["domains"] == nil {
			t.Errorf("%s: domains field is null, want empty array", path)
		}
	}
}
