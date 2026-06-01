package networkfilter

import (
	"fmt"
	"os/exec"
	"strings"
)

// SidecarUID is the UID the nfa sidecar runs as.
// iptables OUTPUT rules exempt this UID so the sidecar can reach real upstreams.
const SidecarUID = 0

type tableRule struct {
	table string
	args  []string
}

func iptablesRules() []tableRule {
	proxyPort := fmt.Sprintf("%d", ProxyPort)
	sidecarUID := fmt.Sprintf("%d", SidecarUID)

	return []tableRule{
		{"filter", []string{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-m", "owner", "--uid-owner", sidecarUID, "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", proxyPort, "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "10.0.0.0/8", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "172.16.0.0/12", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "192.168.0.0/16", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"}},

		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", sidecarUID, "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "10.0.0.0/8", "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "172.16.0.0/12", "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "192.168.0.0/16", "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", proxyPort}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", proxyPort}},
	}
}

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
	for _, rule := range iptablesRules() {
		args := append([]string{"-t", rule.table}, rule.args...)
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables -t %s %v: %w\noutput: %s", rule.table, rule.args, err, out)
		}
	}
	return nil
}

// GenerateIPTablesRestore returns a string in iptables-save/iptables-restore
// format representing the same rules that SetupIPTables would apply.
// Pipe the output to iptables-restore or write it to a file for later use.
func GenerateIPTablesRestore() string {
	// Collect rules grouped by table, preserving insertion order per table.
	type tableBlock struct {
		name  string
		rules []string
	}
	tableIndex := map[string]int{}
	var blocks []tableBlock

	for _, r := range iptablesRules() {
		idx, ok := tableIndex[r.table]
		if !ok {
			idx = len(blocks)
			tableIndex[r.table] = idx
			blocks = append(blocks, tableBlock{name: r.table})
		}
		blocks[idx].rules = append(blocks[idx].rules, strings.Join(r.args, " "))
	}

	var sb strings.Builder
	for _, b := range blocks {
		fmt.Fprintf(&sb, "*%s\n", b.name)
		for _, rule := range b.rules {
			fmt.Fprintf(&sb, "%s\n", rule)
		}
		fmt.Fprintln(&sb, "COMMIT")
	}
	return sb.String()
}
