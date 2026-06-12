package networkfilter

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/takutakahashi/nfa/pkg/policy"
)

// domainsResponse is the JSON body returned by GET /domains.
type domainsResponse struct {
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

// ControlServer exposes a minimal HTTP API on ControlPort (localhost only).
//
//   - POST /enable-policy — activate the configured filter (idempotent)
//   - POST /policy        — replace the configured filter
//   - GET  /domains       — return domains the proxy has actually allowed and denied
type ControlServer struct {
	proxy *Proxy
	store policy.Store
}

// NewControlServer creates a ControlServer that operates on the given proxy.
func NewControlServer(proxy *Proxy, stores ...policy.Store) *ControlServer {
	var store policy.Store
	if len(stores) > 0 {
		store = stores[0]
	}
	return &ControlServer{proxy: proxy, store: store}
}

// Run starts the HTTP control server on lis and blocks until lis is closed.
func (c *ControlServer) Run(lis net.Listener) error {
	srv := &http.Server{Handler: c.Handler()}
	log.Printf("[nfa] control server listening on %s", lis.Addr())
	return srv.Serve(lis)
}

// Handler returns the HTTP handler for the control API.
func (c *ControlServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enable-policy", func(w http.ResponseWriter, _ *http.Request) {
		c.proxy.EnablePolicy()
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "policy enabled")
	})
	mux.HandleFunc("POST /policy", func(w http.ResponseWriter, r *http.Request) {
		var pol policy.Policy
		if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
			http.Error(w, fmt.Sprintf("decode policy: %v", err), http.StatusBadRequest)
			return
		}
		if c.store != nil {
			if err := c.store.Save(pol); err != nil {
				http.Error(w, fmt.Sprintf("persist policy: %v", err), http.StatusInternalServerError)
				return
			}
		}
		c.proxy.SetPolicy(newFilterFromPolicy(pol))
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
	return mux
}

func newFilterFromPolicy(req policy.Policy) *Filter {
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
