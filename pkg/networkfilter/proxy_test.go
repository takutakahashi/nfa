package networkfilter

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestProxyBlocksIPLiteralHTTPHost(t *testing.T) {
	proxy := NewProxy(NewAllowlistFilter([]string{"example.com"}), true)
	client, server := net.Pipe()
	defer client.Close()

	go proxy.handle(server)

	_, _ = fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestProxyCountModePassesBlockedIPLiteralHTTPHost(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer upstream.Close()

	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	proxy := NewProxy(NewCountAllowlistFilter([]string{"example.com"}), true)
	client, server := net.Pipe()
	defer client.Close()

	go proxy.handle(server)

	_, _ = fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.Addr().String())
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestProxyAllowsAllowlistedIPLiteralHTTPHost(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer upstream.Close()

	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	host, _, err := net.SplitHostPort(upstream.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	proxy := NewProxy(NewAllowlistFilter([]string{host}), true)
	client, server := net.Pipe()
	defer client.Close()

	go proxy.handle(server)

	_, _ = fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.Addr().String())
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestProxyAllowsAllowlistedCIDRHTTPHost(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer upstream.Close()

	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	proxy := NewProxy(NewAllowlistFilter([]string{"127.0.0.0/8"}), true)
	client, server := net.Pipe()
	defer client.Close()

	go proxy.handle(server)

	_, _ = fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.Addr().String())
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestProxyHTTPUsesUpstreamProxy(t *testing.T) {
	parent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer parent.Close()

	gotReq := make(chan *http.Request, 1)
	go func() {
		conn, err := parent.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err == nil {
			gotReq <- req
		}
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	proxy := NewProxy(NewAllowlistFilter([]string{"example.com"}), true)
	if err := proxy.SetUpstreamProxy("http://" + parent.Addr().String()); err != nil {
		t.Fatalf("SetUpstreamProxy: %v", err)
	}
	client, server := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	go proxy.handle(server)

	_, _ = fmt.Fprintf(client, "GET /resource?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case req := <-gotReq:
		if req.URL.String() != "http://example.com/resource?q=1" {
			t.Fatalf("parent proxy URL = %q, want absolute-form URL", req.URL.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent proxy did not receive HTTP request")
	}
}

func TestProxyRunHTTPUsesUpstreamProxyOverTCP(t *testing.T) {
	parent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen parent: %v", err)
	}
	defer parent.Close()

	gotReq := make(chan *http.Request, 1)
	go func() {
		conn, err := parent.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err == nil {
			gotReq <- req
		}
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nparent-ok")
	}()

	proxy := NewProxy(NewAllowlistFilter([]string{"example.com"}), true)
	if err := proxy.SetUpstreamProxy("http://" + parent.Addr().String()); err != nil {
		t.Fatalf("SetUpstreamProxy: %v", err)
	}

	proxyLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen proxy: %v", err)
	}
	defer proxyLis.Close()
	go func() {
		_ = proxy.Run(proxyLis)
	}()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyLis.Addr().String()}),
		},
	}
	resp, err := client.Get("http://example.com/resource?q=1")
	if err != nil {
		t.Fatalf("Get through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case req := <-gotReq:
		if req.URL.String() != "http://example.com/resource?q=1" {
			t.Fatalf("parent proxy URL = %q, want absolute-form URL", req.URL.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent proxy did not receive HTTP request")
	}
}

func TestProxyCONNECTUsesUpstreamProxy(t *testing.T) {
	parent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer parent.Close()

	gotReq := make(chan *http.Request, 1)
	go func() {
		conn, err := parent.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		gotReq <- req
		_, _ = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		if string(buf) == "ping" {
			_, _ = fmt.Fprint(conn, "pong")
		}
	}()

	proxy := NewProxy(NewAllowlistFilter([]string{"example.com"}), true)
	if err := proxy.SetUpstreamProxy("http://" + parent.Addr().String()); err != nil {
		t.Fatalf("SetUpstreamProxy: %v", err)
	}
	client, server := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	go proxy.handle(server)

	_, _ = fmt.Fprintf(client, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	_, _ = fmt.Fprint(client, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("ReadFull tunnel response: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("tunnel response = %q, want pong", string(buf))
	}

	select {
	case req := <-gotReq:
		if req.Method != http.MethodConnect {
			t.Fatalf("parent proxy method = %q, want CONNECT", req.Method)
		}
		if req.Host != "example.com:443" {
			t.Fatalf("parent proxy host = %q, want example.com:443", req.Host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent proxy did not receive CONNECT request")
	}
}
