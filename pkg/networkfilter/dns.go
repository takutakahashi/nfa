package networkfilter

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const DNSPort = 5353

type DNSResolverConfig struct {
	Listen      string
	Upstreams   []string
	MaxEntries  int
	MinTTL      time.Duration
	MaxTTL      time.Duration
	NegativeTTL time.Duration
}

func DefaultDNSResolverConfig() DNSResolverConfig {
	return DNSResolverConfig{Listen: fmt.Sprintf("127.0.0.1:%d", DNSPort), MaxEntries: 10000, MinTTL: 5 * time.Second, MaxTTL: time.Hour, NegativeTTL: 30 * time.Second}
}

type dnsCacheEntry struct {
	msg       *dns.Msg
	storedAt  time.Time
	expiresAt time.Time
}

type DNSResolver struct {
	configuredFilter atomic.Pointer[Filter]
	activeFilter     atomic.Pointer[Filter]
	policyActive     atomic.Bool
	log              *domainLog
	config           DNSResolverConfig
	cacheMu          sync.Mutex
	cache            map[string]dnsCacheEntry
	upstreamIndex    atomic.Uint64
}

func NewDNSResolver(filter *Filter, active bool, cfg DNSResolverConfig, domainLog *domainLog) (*DNSResolver, error) {
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf("127.0.0.1:%d", DNSPort)
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	if cfg.MinTTL <= 0 {
		cfg.MinTTL = 5 * time.Second
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = time.Hour
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 30 * time.Second
	}
	if len(cfg.Upstreams) == 0 {
		clientCfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("read system DNS configuration: %w", err)
		}
		for _, server := range clientCfg.Servers {
			cfg.Upstreams = append(cfg.Upstreams, net.JoinHostPort(server, clientCfg.Port))
		}
	}
	for i, upstream := range cfg.Upstreams {
		if _, _, err := net.SplitHostPort(upstream); err != nil {
			cfg.Upstreams[i] = net.JoinHostPort(upstream, "53")
		}
		host, _, err := net.SplitHostPort(cfg.Upstreams[i])
		if err != nil || net.ParseIP(host).To4() == nil {
			return nil, fmt.Errorf("DNS upstream %q must be an IPv4 address", upstream)
		}
	}
	if len(cfg.Upstreams) == 0 {
		return nil, fmt.Errorf("no DNS upstream configured")
	}
	r := &DNSResolver{config: cfg, cache: make(map[string]dnsCacheEntry), log: domainLog}
	r.configuredFilter.Store(filter)
	if active {
		r.activeFilter.Store(filter)
		r.policyActive.Store(true)
	}
	return r, nil
}

// NewDNSResolverForProxy creates a resolver that shares the proxy's domain audit log.
func NewDNSResolverForProxy(filter *Filter, active bool, cfg DNSResolverConfig, proxy *Proxy) (*DNSResolver, error) {
	return NewDNSResolver(filter, active, cfg, &proxy.log)
}

func (r *DNSResolver) EnablePolicy() {
	r.activeFilter.Store(r.configuredFilter.Load())
	r.policyActive.Store(true)
	r.FlushCache()
}
func (r *DNSResolver) SetPolicy(filter *Filter) {
	r.configuredFilter.Store(filter)
	if r.policyActive.Load() {
		r.activeFilter.Store(filter)
	}
	r.FlushCache()
}
func (r *DNSResolver) FlushCache() {
	r.cacheMu.Lock()
	r.cache = make(map[string]dnsCacheEntry)
	r.cacheMu.Unlock()
}

func (r *DNSResolver) effectiveFilter() *Filter {
	if f := r.activeFilter.Load(); f != nil {
		return f
	}
	return passthroughFilter
}

func (r *DNSResolver) Run() error {
	udp := &dns.Server{Addr: r.config.Listen, Net: "udp", Handler: r}
	tcp := &dns.Server{Addr: r.config.Listen, Net: "tcp", Handler: r}
	errs := make(chan error, 2)
	go func() { errs <- udp.ListenAndServe() }()
	go func() { errs <- tcp.ListenAndServe() }()
	log.Printf("[nfa] DNS resolver listening on %s (upstreams=%v)", r.config.Listen, r.config.Upstreams)
	return <-errs
}

// Start binds both UDP and TCP listeners before returning, so startup cannot
// silently continue without DNS enforcement.
func (r *DNSResolver) Start() error {
	packetConn, err := net.ListenPacket("udp", r.config.Listen)
	if err != nil {
		return fmt.Errorf("listen DNS UDP %s: %w", r.config.Listen, err)
	}
	listener, err := net.Listen("tcp", r.config.Listen)
	if err != nil {
		_ = packetConn.Close()
		return fmt.Errorf("listen DNS TCP %s: %w", r.config.Listen, err)
	}
	udp := &dns.Server{PacketConn: packetConn, Handler: r}
	tcp := &dns.Server{Listener: listener, Handler: r}
	go func() {
		if err := udp.ActivateAndServe(); err != nil {
			log.Printf("[nfa] DNS UDP server error: %v", err)
		}
	}()
	go func() {
		if err := tcp.ActivateAndServe(); err != nil {
			log.Printf("[nfa] DNS TCP server error: %v", err)
		}
	}()
	log.Printf("[nfa] DNS resolver listening on %s (upstreams=%v)", r.config.Listen, r.config.Upstreams)
	return nil
}

func (r *DNSResolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		rcodeReply(w, req, dns.RcodeFormatError)
		return
	}
	q := req.Question[0]
	host := normalizeHost(q.Name)
	result := r.effectiveFilter().Check(host)
	if r.log != nil {
		r.log.record(host, result)
	}
	if result == FilterResultBlocked && !r.effectiveFilter().IsCountMode() {
		log.Printf("[nfa] DNS blocked: %s %s", host, dns.TypeToString[q.Qtype])
		rcodeReply(w, req, dns.RcodeRefused)
		return
	}
	key := dnsCacheKey(req)
	if cached := r.cached(key); cached != nil {
		cached.Id = req.Id
		_ = w.WriteMsg(cached)
		return
	}
	resp, err := r.exchange(req)
	if err != nil {
		log.Printf("[nfa] DNS upstream error for %s: %v", host, err)
		rcodeReply(w, req, dns.RcodeServerFailure)
		return
	}
	r.store(key, resp)
	resp.Id = req.Id
	_ = w.WriteMsg(resp)
}

func rcodeReply(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	msg := new(dns.Msg)
	msg.SetRcode(req, rcode)
	_ = w.WriteMsg(msg)
}

func dnsCacheKey(req *dns.Msg) string {
	q := req.Question[0]
	do := false
	if opt := req.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	return fmt.Sprintf("%s|%d|%d|%t", strings.ToLower(q.Name), q.Qtype, q.Qclass, do)
}

func (r *DNSResolver) exchange(req *dns.Msg) (*dns.Msg, error) {
	forward := req.Copy()
	if opt := forward.IsEdns0(); opt != nil {
		filtered := opt.Option[:0]
		for _, option := range opt.Option {
			if option.Option() != dns.EDNS0SUBNET {
				filtered = append(filtered, option)
			}
		}
		opt.Option = filtered
	}
	var lastErr error
	for i := 0; i < len(r.config.Upstreams); i++ {
		idx := (int(r.upstreamIndex.Add(1)) - 1 + i) % len(r.config.Upstreams)
		client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		resp, _, err := client.ExchangeContext(context.Background(), forward, r.config.Upstreams[idx])
		if err == nil && resp.Truncated {
			client.Net = "tcp"
			resp, _, err = client.ExchangeContext(context.Background(), forward, r.config.Upstreams[idx])
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *DNSResolver) cached(key string) *dns.Msg {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	entry, ok := r.cache[key]
	if !ok {
		return nil
	}
	now := time.Now()
	if !now.Before(entry.expiresAt) {
		delete(r.cache, key)
		return nil
	}
	msg := entry.msg.Copy()
	elapsed := uint32(now.Sub(entry.storedAt) / time.Second)
	updateMsgTTL(msg, func(ttl uint32) uint32 {
		if elapsed >= ttl {
			return 0
		}
		return ttl - elapsed
	})
	return msg
}

func (r *DNSResolver) store(key string, msg *dns.Msg) {
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return
	}
	ttl := r.cacheTTL(msg)
	if ttl <= 0 {
		return
	}
	copy := msg.Copy()
	seconds := uint32(ttl / time.Second)
	updateMsgTTL(copy, func(uint32) uint32 { return seconds })
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if len(r.cache) >= r.config.MaxEntries {
		var oldestKey string
		var oldest time.Time
		for k, entry := range r.cache {
			if oldestKey == "" || entry.storedAt.Before(oldest) {
				oldestKey, oldest = k, entry.storedAt
			}
		}
		delete(r.cache, oldestKey)
	}
	now := time.Now()
	r.cache[key] = dnsCacheEntry{msg: copy, storedAt: now, expiresAt: now.Add(ttl)}
}

func (r *DNSResolver) cacheTTL(msg *dns.Msg) time.Duration {
	var ttl uint32
	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		ttl = uint32(r.config.NegativeTTL / time.Second)
		for _, rr := range msg.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl = soa.Hdr.Ttl
				if soa.Minttl < ttl {
					ttl = soa.Minttl
				}
				break
			}
		}
	} else {
		for _, rr := range append(append([]dns.RR{}, msg.Answer...), msg.Ns...) {
			if ttl == 0 || rr.Header().Ttl < ttl {
				ttl = rr.Header().Ttl
			}
		}
	}
	d := time.Duration(ttl) * time.Second
	if d < r.config.MinTTL {
		d = r.config.MinTTL
	}
	if d > r.config.MaxTTL {
		d = r.config.MaxTTL
	}
	return d
}

func updateMsgTTL(msg *dns.Msg, fn func(uint32) uint32) {
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl = fn(rr.Header().Ttl)
			}
		}
	}
}
