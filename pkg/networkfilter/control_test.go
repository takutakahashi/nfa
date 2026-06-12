package networkfilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/takutakahashi/nfa/pkg/policy"
)

type recordingPolicyStore struct {
	policy policy.Policy
	err    error
	calls  int
}

func (s *recordingPolicyStore) Save(pol policy.Policy) error {
	s.calls++
	s.policy = pol
	return s.err
}

type recordingDirectAllowlistUpdater struct {
	entries []string
	err     error
	calls   int
}

func (u *recordingDirectAllowlistUpdater) UpdateDirectAllowlist(entries []string) error {
	u.calls++
	u.entries = append([]string(nil), entries...)
	return u.err
}

func newControlHandler(proxy *Proxy, stores ...policy.Store) http.Handler {
	return NewControlServer(proxy, stores...).Handler()
}

func getDomainsResponse(t *testing.T, handler http.Handler) domainsResponse {
	t.Helper()
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
	return body
}

func TestControlDomainsEmptyBeforeTraffic(t *testing.T) {
	proxy := NewProxy(NewAllowlistFilter([]string{"example.com"}), true)
	handler := newControlHandler(proxy)

	body := getDomainsResponse(t, handler)
	if body.Allowed == nil {
		t.Error("allowed is null, want empty array")
	}
	if body.Denied == nil {
		t.Error("denied is null, want empty array")
	}
	if len(body.Allowed) != 0 || len(body.Denied) != 0 {
		t.Errorf("expected empty lists before any traffic, got allowed=%v denied=%v", body.Allowed, body.Denied)
	}
}

func TestControlDomainsRecordsAllowed(t *testing.T) {
	proxy := NewProxy(NewAllowlistFilter([]string{"example.com", "*.trusted.io"}), true)
	handler := newControlHandler(proxy)

	// simulate traffic
	proxy.log.record("example.com", FilterResultAllowed)
	proxy.log.record("sub.trusted.io", FilterResultAllowed)
	proxy.log.record("api.anthropic.com", FilterResultBypassed)

	body := getDomainsResponse(t, handler)
	sort.Strings(body.Allowed)
	want := []string{"api.anthropic.com", "example.com", "sub.trusted.io"}
	sort.Strings(want)
	if len(body.Allowed) != len(want) {
		t.Errorf("allowed = %v, want %v", body.Allowed, want)
	}
	for i := range want {
		if body.Allowed[i] != want[i] {
			t.Errorf("allowed[%d] = %q, want %q", i, body.Allowed[i], want[i])
		}
	}
	if len(body.Denied) != 0 {
		t.Errorf("denied = %v, want empty", body.Denied)
	}
}

func TestControlDomainsRecordsDenied(t *testing.T) {
	proxy := NewProxy(NewAllowlistFilter([]string{"example.com"}), true)
	handler := newControlHandler(proxy)

	proxy.log.record("bad.com", FilterResultBlocked)
	proxy.log.record("evil.org", FilterResultBlocked)
	proxy.log.record("example.com", FilterResultAllowed)

	body := getDomainsResponse(t, handler)
	sort.Strings(body.Denied)
	wantDenied := []string{"bad.com", "evil.org"}
	if len(body.Denied) != len(wantDenied) {
		t.Errorf("denied = %v, want %v", body.Denied, wantDenied)
	}
	for i := range wantDenied {
		if body.Denied[i] != wantDenied[i] {
			t.Errorf("denied[%d] = %q, want %q", i, body.Denied[i], wantDenied[i])
		}
	}
	if len(body.Allowed) != 1 || body.Allowed[0] != "example.com" {
		t.Errorf("allowed = %v, want [example.com]", body.Allowed)
	}
}

func TestControlDomainsDeduplicates(t *testing.T) {
	proxy := NewProxy(NewFilter(nil), true)
	handler := newControlHandler(proxy)

	// same domain recorded multiple times
	for i := 0; i < 5; i++ {
		proxy.log.record("repeated.com", FilterResultAllowed)
	}

	body := getDomainsResponse(t, handler)
	if len(body.Allowed) != 1 {
		t.Errorf("allowed = %v (len %d), want exactly 1 unique entry", body.Allowed, len(body.Allowed))
	}
}

func TestControlPolicyUpdatesActiveFilter(t *testing.T) {
	proxy := NewProxy(NewFilter(nil), true)
	handler := newControlHandler(proxy)

	body := bytes.NewBufferString(`{"allowed":["example.com"],"count_mode":true}`)
	req := httptest.NewRequest(http.MethodPost, "/policy", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	filter := proxy.effectiveFilter()
	if !filter.IsCountMode() {
		t.Fatal("updated filter IsCountMode() = false, want true")
	}
	if got := filter.Check("blocked.example.net"); got != FilterResultBlocked {
		t.Fatalf("Check(blocked.example.net) = %s, want blocked", got)
	}
}

func TestControlPolicyUpdatesDirectAllowlist(t *testing.T) {
	proxy := NewProxy(NewFilter(nil), true)
	updater := &recordingDirectAllowlistUpdater{}
	control := NewControlServer(proxy)
	control.SetDirectAllowlistUpdater(updater)
	handler := control.Handler()

	body := bytes.NewBufferString(`{"allowed":["example.com","192.0.2.10","198.51.100.0/24"]}`)
	req := httptest.NewRequest(http.MethodPost, "/policy", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if updater.calls != 1 {
		t.Fatalf("updater calls = %d, want 1", updater.calls)
	}
	want := []string{"example.com", "192.0.2.10", "198.51.100.0/24"}
	if strings.Join(updater.entries, ",") != strings.Join(want, ",") {
		t.Fatalf("updater entries = %v, want %v", updater.entries, want)
	}
}

func TestControlPolicyDoesNotUpdateFilterWhenDirectAllowlistFails(t *testing.T) {
	proxy := NewProxy(NewFilter([]string{"old.example"}), true)
	updater := &recordingDirectAllowlistUpdater{err: errors.New("iptables failed")}
	control := NewControlServer(proxy)
	control.SetDirectAllowlistUpdater(updater)
	handler := control.Handler()

	body := bytes.NewBufferString(`{"allowed":["new.example","192.0.2.10"]}`)
	req := httptest.NewRequest(http.MethodPost, "/policy", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}

	filter := proxy.effectiveFilter()
	if got := filter.Check("new.example"); got != FilterResultAllowed {
		t.Fatalf("Check(new.example) = %s, want allowed", got)
	}
	if got := filter.Check("old.example"); got != FilterResultBlocked {
		t.Fatalf("Check(old.example) = %s, want blocked", got)
	}
}

func TestControlPolicyPersistsPolicy(t *testing.T) {
	proxy := NewProxy(NewFilter(nil), true)
	store := &recordingPolicyStore{}
	handler := newControlHandler(proxy, store)

	body := bytes.NewBufferString(`{"denied":["bad.example"],"count_mode":true}`)
	req := httptest.NewRequest(http.MethodPost, "/policy", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if store.calls != 1 {
		t.Fatalf("store calls = %d, want 1", store.calls)
	}
	if !store.policy.CountMode {
		t.Fatal("stored CountMode = false, want true")
	}
	if len(store.policy.Denied) != 1 || store.policy.Denied[0] != "bad.example" {
		t.Fatalf("stored Denied = %v, want [bad.example]", store.policy.Denied)
	}
}

func TestControlPolicyDoesNotUpdateFilterWhenPersistenceFails(t *testing.T) {
	proxy := NewProxy(NewFilter([]string{"old.example"}), true)
	store := &recordingPolicyStore{err: errors.New("disk full")}
	handler := newControlHandler(proxy, store)

	body := bytes.NewBufferString(`{"denied":["new.example"]}`)
	req := httptest.NewRequest(http.MethodPost, "/policy", body)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}

	filter := proxy.effectiveFilter()
	if got := filter.Check("new.example"); got != FilterResultAllowed {
		t.Fatalf("Check(new.example) = %s, want allowed", got)
	}
	if got := filter.Check("old.example"); got != FilterResultBlocked {
		t.Fatalf("Check(old.example) = %s, want blocked", got)
	}
}
