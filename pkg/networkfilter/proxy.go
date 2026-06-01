package networkfilter

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ProxyPort is the port the forward proxy listens on.
	ProxyPort = 3128

	// ControlPort is the port the control server listens on (localhost only).
	ControlPort = 3129

	dialTimeout = 10 * time.Second
)

var passthroughFilter = &Filter{}

// domainLog records unique domains that the proxy has allowed or denied.
type domainLog struct {
	mu      sync.RWMutex
	allowed map[string]struct{}
	denied  map[string]struct{}
}

func newDomainLog() domainLog {
	return domainLog{
		allowed: make(map[string]struct{}),
		denied:  make(map[string]struct{}),
	}
}

func (d *domainLog) record(host string, result FilterResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if result == FilterResultBlocked {
		d.denied[host] = struct{}{}
	} else {
		d.allowed[host] = struct{}{}
	}
}

func (d *domainLog) snapshot() (allowed, denied []string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	allowed = make([]string, 0, len(d.allowed))
	for h := range d.allowed {
		allowed = append(allowed, h)
	}
	denied = make([]string, 0, len(d.denied))
	for h := range d.denied {
		denied = append(denied, h)
	}
	return
}

// Proxy is a forward proxy that enforces a domain filter.
// It handles HTTP CONNECT tunnels, HTTP forward requests, and transparent TCP
// (iptables-redirected port 80/443) on a single port.
type Proxy struct {
	configuredFilter *Filter
	activeFilter     atomic.Pointer[Filter]
	log              domainLog
}

// NewProxy creates a Proxy with the given filter.
// When active is true, the policy is enforced immediately.
// When active is false, all traffic is allowed until EnablePolicy is called.
func NewProxy(filter *Filter, active bool) *Proxy {
	p := &Proxy{configuredFilter: filter, log: newDomainLog()}
	if active {
		p.activeFilter.Store(filter)
	}
	return p
}

// EnablePolicy activates the configured filter.
func (p *Proxy) EnablePolicy() {
	p.activeFilter.Store(p.configuredFilter)
	log.Printf("[nfa] policy enabled")
}

func (p *Proxy) effectiveFilter() *Filter {
	if f := p.activeFilter.Load(); f != nil {
		return f
	}
	return passthroughFilter
}

// Run starts the proxy on the given listener and blocks until lis is closed.
func (p *Proxy) Run(lis net.Listener) error {
	log.Printf("[nfa] proxy listening on %s", lis.Addr())
	for {
		conn, err := lis.Accept()
		if err != nil {
			return err
		}
		go p.handle(conn)
	}
}

func (p *Proxy) handle(conn net.Conn) {
	defer conn.Close() //nolint:errcheck

	br := bufio.NewReaderSize(conn, 4096)

	first, err := br.Peek(1)
	if err != nil {
		return
	}

	if first[0] == 0x16 {
		p.handleTransparentTLS(conn, br)
		return
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleCONNECT(conn, req)
	} else {
		p.handleHTTP(conn, br, req)
	}
}

func (p *Proxy) handleCONNECT(conn net.Conn, req *http.Request) {
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}

	f := p.effectiveFilter()
	result := f.Check(host)
	p.log.record(host, result)
	if result == FilterResultBlocked && f.IsCountMode() {
		log.Printf("[nfa] CONNECT count-blocked (passed through): %s", req.Host)
	} else {
		log.Printf("[nfa] CONNECT %s: %s", result, req.Host)
	}

	if result == FilterResultBlocked && !f.IsCountMode() {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\n\r\nblocked by network filter\n")
		return
	}

	upConn, err := net.DialTimeout("tcp", req.Host, dialTimeout)
	if err != nil {
		log.Printf("[nfa] CONNECT dial error %s: %v", req.Host, err)
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n%v\n", err)
		return
	}
	defer upConn.Close() //nolint:errcheck

	_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	pipe(conn, upConn)
}

func (p *Proxy) handleHTTP(conn net.Conn, br *bufio.Reader, req *http.Request) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	f := p.effectiveFilter()
	result := f.Check(host)
	p.log.record(host, result)
	if result == FilterResultBlocked && f.IsCountMode() {
		log.Printf("[nfa] HTTP count-blocked (passed through): %s", host)
	} else {
		log.Printf("[nfa] HTTP %s: %s", result, host)
	}

	if result == FilterResultBlocked && !f.IsCountMode() {
		resp := &http.Response{
			Status:     "403 Forbidden",
			StatusCode: http.StatusForbidden,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Type": []string{"text/plain"}, "Connection": []string{"close"}},
			Body:       io.NopCloser(strings.NewReader("blocked by network filter\n")),
		}
		_ = resp.Write(conn)
		return
	}

	upstream := req.Host
	if upstream == "" {
		upstream = req.URL.Host
	}
	if !strings.Contains(upstream, ":") {
		upstream = net.JoinHostPort(upstream, "80")
	}

	upConn, err := net.DialTimeout("tcp", upstream, dialTimeout)
	if err != nil {
		log.Printf("[nfa] HTTP dial error %s: %v", upstream, err)
		resp := &http.Response{
			Status:     "502 Bad Gateway",
			StatusCode: http.StatusBadGateway,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("dial error: %v\n", err))),
		}
		_ = resp.Write(conn)
		return
	}
	defer upConn.Close() //nolint:errcheck

	req.RequestURI = req.URL.RequestURI()
	if err := req.Write(upConn); err != nil {
		return
	}
	pipe(conn, upConn)
}

func (p *Proxy) handleTransparentTLS(conn net.Conn, br *bufio.Reader) {
	sni, raw, err := PeekSNI(br)
	if err != nil {
		log.Printf("[nfa] TLS: SNI parse error (fail-open): %v", err)
		return
	}

	f := p.effectiveFilter()
	result := f.Check(sni)
	p.log.record(sni, result)
	if result == FilterResultBlocked && f.IsCountMode() {
		log.Printf("[nfa] TLS count-blocked (passed through): %s", sni)
	} else {
		log.Printf("[nfa] TLS %s: %s", result, sni)
	}

	if result == FilterResultBlocked && !f.IsCountMode() {
		return
	}

	upstream := net.JoinHostPort(sni, "443")
	upConn, err := net.DialTimeout("tcp", upstream, dialTimeout)
	if err != nil {
		log.Printf("[nfa] TLS dial error %s: %v", upstream, err)
		return
	}
	defer upConn.Close() //nolint:errcheck

	if _, err := upConn.Write(raw); err != nil {
		return
	}
	pipe(io.MultiReader(br, conn), upConn, conn)
}

func pipe(a, b interface{ Read([]byte) (int, error) }, extras ...io.Writer) {
	aConn, aOK := a.(net.Conn)
	bConn, bOK := b.(net.Conn)
	if !aOK || !bOK {
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(b.(io.Writer), a.(io.Reader)); done <- struct{}{} }()
		go func() {
			if len(extras) > 0 {
				_, _ = io.Copy(io.MultiWriter(extras...), b.(io.Reader))
			} else {
				_, _ = io.Copy(a.(io.Writer), b.(io.Reader))
			}
			done <- struct{}{}
		}()
		<-done
		return
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(bConn, aConn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(aConn, bConn); done <- struct{}{} }()
	<-done
}
