package networkfilter

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
)

// ControlServer exposes a minimal HTTP API on ControlPort (localhost only).
//
//   - POST /enable-policy   — activate the configured filter (idempotent)
//   - GET  /domains/allowed — list allowed domains (non-empty in allowlist mode)
//   - GET  /domains/denied  — list denied domains (non-empty in denylist mode)
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
	mux.HandleFunc("GET /domains/allowed", func(w http.ResponseWriter, _ *http.Request) {
		domains := c.proxy.configuredFilter.AllowedDomains()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"domains": domains})
	})
	mux.HandleFunc("GET /domains/denied", func(w http.ResponseWriter, _ *http.Request) {
		domains := c.proxy.configuredFilter.DeniedDomains()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"domains": domains})
	})
	srv := &http.Server{Handler: mux}
	log.Printf("[nfa] control server listening on %s", lis.Addr())
	return srv.Serve(lis)
}
