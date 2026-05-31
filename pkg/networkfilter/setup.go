package networkfilter

import (
	"fmt"
	"os/exec"
)

// SidecarUID is the UID the nfa sidecar runs as.
// iptables OUTPUT rules exempt this UID so the sidecar can reach real upstreams.
const SidecarUID = 0

// SetupIPTables configures iptables rules for network isolation:
//   - All outbound TCP is rejected by default.
//   - Traffic from the sidecar (UID 0) is exempted.
//   - The proxy port (127.0.0.1:3128) is allowed for the main container.
//   - Established/related packets pass through.
//   - RFC1918 cluster-internal addresses are allowed.
//   - Port 80/443 is transparently redirected to the proxy port.
//
// Requires CAP_NET_ADMIN.
func SetupIPTables() error {
	proxyPort := fmt.Sprintf("%d", ProxyPort)
	sidecarUID := fmt.Sprintf("%d", SidecarUID)

	rules := [][]string{
		{"-t", "filter", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-m", "owner", "--uid-owner", sidecarUID, "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", proxyPort, "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-p", "tcp", "-d", "10.0.0.0/8", "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-p", "tcp", "-d", "172.16.0.0/12", "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-p", "tcp", "-d", "192.168.0.0/16", "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"},

		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "-j", "RETURN"},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", sidecarUID, "-j", "RETURN"},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "10.0.0.0/8", "-j", "RETURN"},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "172.16.0.0/12", "-j", "RETURN"},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "192.168.0.0/16", "-j", "RETURN"},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", proxyPort},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", proxyPort},
	}

	for _, rule := range rules {
		cmd := exec.Command("iptables", rule...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %v: %w\noutput: %s", rule, err, out)
		}
	}
	return nil
}
