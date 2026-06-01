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
	Mode    string   `json:"mode"`
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

// ControlServer exposes a minimal HTTP API on ControlPort (localhost only).
//
//   - POST /enable-policy — activate the configured filter (idempotent)
//   - GET  /domains       — return allow/deny domain lists and active mode
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
	mux.HandleFunc("GET /domains", func(w http.ResponseWriter, _ *http.Request) {
		f := c.proxy.configuredFilter
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
	srv := &http.Server{Handler: mux}
	log.Printf("[nfa] control server listening on %s", lis.Addr())
	return srv.Serve(lis)
}
