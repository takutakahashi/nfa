package networkfilter

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
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
