package networkfilter

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// SidecarUID is the UID the nfa sidecar runs as.
// iptables OUTPUT rules exempt this UID so the sidecar can reach real upstreams.
const SidecarUID = 0

const (
	directAllowFilterChain = "NFA_DIRECT_ALLOW"
	directAllowNATChain    = "NFA_DIRECT_ALLOW"
)

type tableRule struct {
	table string
	args  []string
}

func iptablesRules() []tableRule {
	proxyPort := fmt.Sprintf("%d", ProxyPort)
	sidecarUID := fmt.Sprintf("%d", SidecarUID)

	return []tableRule{
		{"filter", []string{"-N", directAllowFilterChain}},
		{"filter", []string{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-m", "owner", "--uid-owner", sidecarUID, "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", proxyPort, "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-j", directAllowFilterChain}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"}},

		{"nat", []string{"-N", directAllowNATChain}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", sidecarUID, "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-j", directAllowNATChain}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", proxyPort}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", proxyPort}},
	}
}

// SetupIPTables configures iptables rules for network isolation:
//   - All outbound TCP is rejected by default.
//   - Traffic from the sidecar (UID 0) is exempted.
//   - The proxy port (127.0.0.1:3128) is allowed for the main container.
//   - Established/related packets pass through.
//   - Port 80/443 is transparently redirected to the proxy port.
//
// Requires CAP_NET_ADMIN.
func SetupIPTables() error {
	return SetupIPTablesWithDirectAllowlist(nil)
}

// SetupIPTablesWithDirectAllowlist configures the base isolation rules and
// adds direct TCP bypasses for IPv4 addresses and CIDRs in entries. The NAT
// bypass happens before the HTTP/TLS redirects, so allowlisted destinations
// never reach the proxy and are not subject to SNI inspection.
func SetupIPTablesWithDirectAllowlist(entries []string) error {
	for _, rule := range iptablesRules() {
		args := append([]string{"-t", rule.table}, rule.args...)
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables -t %s %v: %w\noutput: %s", rule.table, rule.args, err, out)
		}
	}
	for _, cidr := range DirectAllowlistCIDRs(entries) {
		if err := runIPTables("filter", "-A", directAllowFilterChain, "-p", "tcp", "-d", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := runIPTables("nat", "-A", directAllowNATChain, "-p", "tcp", "-d", cidr, "-j", "RETURN"); err != nil {
			return err
		}
	}
	return nil
}

// UpdateDirectAllowlist configures direct TCP destinations that bypass the
// transparent HTTP/TLS redirects (and therefore SNI inspection) and the
// default TCP reject rule. Only IPv4 addresses and CIDRs are applied;
// hostnames remain proxy-only policy entries.
func UpdateDirectAllowlist(entries []string) error {
	cidrs := DirectAllowlistCIDRs(entries)
	if err := ensureDirectAllowlistChains(); err != nil {
		return err
	}
	if err := flushChain("filter", directAllowFilterChain); err != nil {
		return err
	}
	if err := flushChain("nat", directAllowNATChain); err != nil {
		return err
	}
	for _, cidr := range cidrs {
		if err := runIPTables("filter", "-A", directAllowFilterChain, "-p", "tcp", "-d", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := runIPTables("nat", "-A", directAllowNATChain, "-p", "tcp", "-d", cidr, "-j", "RETURN"); err != nil {
			return err
		}
	}
	return nil
}

// IPTablesDirectAllowlistUpdater applies direct allowlist entries with iptables.
type IPTablesDirectAllowlistUpdater struct{}

func (IPTablesDirectAllowlistUpdater) UpdateDirectAllowlist(entries []string) error {
	return UpdateDirectAllowlist(entries)
}

func ensureDirectAllowlistChains() error {
	for _, table := range []string{"filter", "nat"} {
		chain := directAllowFilterChain
		if table == "nat" {
			chain = directAllowNATChain
		}
		if err := runIPTablesAllowExists(table, "-N", chain); err != nil {
			return err
		}
		if err := ensureOutputJump(table, chain); err != nil {
			return err
		}
	}
	return nil
}

func ensureOutputJump(table, chain string) error {
	checkArgs := []string{"-t", table, "-C", "OUTPUT", "-p", "tcp", "-j", chain}
	if err := exec.Command("iptables", checkArgs...).Run(); err == nil {
		return nil
	}
	return runIPTables(table, "-I", "OUTPUT", "1", "-p", "tcp", "-j", chain)
}

func flushChain(table, chain string) error {
	return runIPTables(table, "-F", chain)
}

func runIPTables(table string, args ...string) error {
	cmdArgs := append([]string{"-t", table}, args...)
	if out, err := exec.Command("iptables", cmdArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %v: %w\noutput: %s", cmdArgs, err, out)
	}
	return nil
}

func runIPTablesAllowExists(table string, args ...string) error {
	cmdArgs := append([]string{"-t", table}, args...)
	if out, err := exec.Command("iptables", cmdArgs...).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Chain already exists") {
			return nil
		}
		return fmt.Errorf("iptables %v: %w\noutput: %s", cmdArgs, err, out)
	}
	return nil
}

// DirectAllowlistCIDRs extracts IPv4 addresses and CIDRs from policy entries.
func DirectAllowlistCIDRs(entries []string) []string {
	out := make([]string, 0, len(entries))
	seen := map[string]struct{}{}
	for _, entry := range entries {
		cidr, ok := directAllowlistCIDR(entry)
		if !ok {
			continue
		}
		if _, exists := seen[cidr]; exists {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out
}

func directAllowlistCIDR(entry string) (string, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", false
	}
	ip := net.ParseIP(entry)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String() + "/32", true
	}
	_, ipNet, err := net.ParseCIDR(entry)
	if err != nil {
		return "", false
	}
	if ipNet.IP.To4() == nil {
		return "", false
	}
	return ipNet.String(), true
}

// GenerateIPTablesRestore returns a string in iptables-save/iptables-restore
// format representing the same rules that SetupIPTables would apply.
// Pipe the output to iptables-restore or write it to a file for later use.
func GenerateIPTablesRestore() string {
	return GenerateIPTablesRestoreWithDirectAllowlist(nil)
}

// GenerateIPTablesRestoreWithDirectAllowlist returns the base restore rules
// plus direct TCP bypasses for IPv4 addresses and CIDRs in entries. The NAT
// rules return before the TLS redirect, preventing SNI inspection.
func GenerateIPTablesRestoreWithDirectAllowlist(entries []string) string {
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
	for _, cidr := range DirectAllowlistCIDRs(entries) {
		filterIdx := tableIndex["filter"]
		blocks[filterIdx].rules = append(blocks[filterIdx].rules,
			strings.Join([]string{"-A", directAllowFilterChain, "-p", "tcp", "-d", cidr, "-j", "ACCEPT"}, " "))
		natIdx := tableIndex["nat"]
		blocks[natIdx].rules = append(blocks[natIdx].rules,
			strings.Join([]string{"-A", directAllowNATChain, "-p", "tcp", "-d", cidr, "-j", "RETURN"}, " "))
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
