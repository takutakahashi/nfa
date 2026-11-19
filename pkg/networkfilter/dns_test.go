package networkfilter

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type captureDNSWriter struct{ msg *dns.Msg }

func (w *captureDNSWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (w *captureDNSWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (w *captureDNSWriter) WriteMsg(msg *dns.Msg) error { w.msg = msg.Copy(); return nil }
func (w *captureDNSWriter) Write([]byte) (int, error)   { return 0, nil }
func (w *captureDNSWriter) Close() error                { return nil }
func (w *captureDNSWriter) TsigStatus() error           { return nil }
func (w *captureDNSWriter) TsigTimersOnly(bool)         {}
func (w *captureDNSWriter) Hijack()                     {}

func startTestUpstream(t *testing.T, calls *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		calls.Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.10")}}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

func dnsQuery(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return req
}

func TestDNSResolverBlocksWithoutForwarding(t *testing.T) {
	var calls atomic.Int32
	resolver, err := NewDNSResolver(NewAllowlistFilter([]string{"allowed.example"}), true, DNSResolverConfig{Upstreams: []string{startTestUpstream(t, &calls)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &captureDNSWriter{}
	resolver.ServeDNS(w, dnsQuery("blocked.example"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %v, want REFUSED", w.msg)
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream calls = %d, want 0", calls.Load())
	}
}

func TestDNSResolverCachesAndFlushesOnPolicyChange(t *testing.T) {
	var calls atomic.Int32
	resolver, err := NewDNSResolver(NewAllowlistFilter([]string{"allowed.example"}), true, DNSResolverConfig{Upstreams: []string{startTestUpstream(t, &calls)}, MinTTL: time.Second, MaxTTL: time.Minute}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		w := &captureDNSWriter{}
		resolver.ServeDNS(w, dnsQuery("allowed.example"))
		if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess {
			t.Fatalf("query %d failed: %#v", i, w.msg)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
	resolver.SetPolicy(NewAllowlistFilter([]string{"allowed.example"}))
	w := &captureDNSWriter{}
	resolver.ServeDNS(w, dnsQuery("allowed.example"))
	if calls.Load() != 2 {
		t.Fatalf("upstream calls after policy update = %d, want 2", calls.Load())
	}
}

func TestDNSResolverCountModeForwardsBlockedQuery(t *testing.T) {
	var calls atomic.Int32
	resolver, err := NewDNSResolver(NewCountAllowlistFilter(nil), true, DNSResolverConfig{Upstreams: []string{startTestUpstream(t, &calls)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &captureDNSWriter{}
	resolver.ServeDNS(w, dnsQuery("observed.example"))
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("response = %#v", w.msg)
	}
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
}
