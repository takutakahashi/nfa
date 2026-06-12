package networkfilter

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
)

// domainsResponse is the JSON body returned by GET /domains.
type domainsResponse struct {
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

type policyRequest struct {
	Allowed   []string `json:"allowed,omitempty"`
	Denied    []string `json:"denied,omitempty"`
	CountMode bool     `json:"count_mode,omitempty"`
}

// ControlServer exposes a minimal HTTP API on a TCP or Unix domain socket listener.
//
//   - POST /enable-policy — activate the configured filter (idempotent)
//   - POST /policy        — replace the configured filter
//   - GET  /domains       — return domains the proxy has actually allowed and denied
type ControlServer struct {
	proxy *Proxy
}

// NewControlServer creates a ControlServer that operates on the given proxy.
func NewControlServer(proxy *Proxy) *ControlServer {
	return &ControlServer{proxy: proxy}
}

// Run starts the HTTP control server on lis and blocks until lis is closed.
func (c *ControlServer) Run(lis net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enable-policy", func(w http.ResponseWriter, _ *http.Request) {
		c.proxy.EnablePolicy()
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "policy enabled")
	})
	mux.HandleFunc("POST /policy", func(w http.ResponseWriter, r *http.Request) {
		var req policyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("decode policy: %v", err), http.StatusBadRequest)
			return
		}
		c.proxy.SetPolicy(newFilterFromPolicy(req))
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "policy configured")
	})
	mux.HandleFunc("GET /domains", func(w http.ResponseWriter, _ *http.Request) {
		allowed, denied := c.proxy.log.snapshot()
		resp := domainsResponse{
			Allowed: allowed,
			Denied:  denied,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := &http.Server{Handler: mux}
	log.Printf("[nfa] control server listening on %s", lis.Addr())
	return srv.Serve(lis)
}

func newFilterFromPolicy(req policyRequest) *Filter {
	switch {
	case len(req.Allowed) > 0:
		if req.CountMode {
			return NewCountAllowlistFilter(req.Allowed)
		}
		return NewAllowlistFilter(req.Allowed)
	case len(req.Denied) > 0:
		if req.CountMode {
			return NewCountFilter(req.Denied)
		}
		return NewFilter(req.Denied)
	default:
		if req.CountMode {
			return NewCountAllowlistFilter(nil)
		}
		return NewAllowlistFilter(nil)
	}
}
