package networkfilter

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type tableRule struct {
	table string
	args  []string
}

// CurrentUID returns the UID that should be exempted by default.
func CurrentUID() int {
	return os.Getuid()
}

// ParseUID validates a UID string.
func ParseUID(value string) (int, error) {
	uid, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parse uid %q: %w", value, err)
	}
	if uid < 0 {
		return 0, fmt.Errorf("uid must be non-negative: %d", uid)
	}
	return uid, nil
}

func iptablesRules(sidecarUID int) []tableRule {
	proxyPort := fmt.Sprintf("%d", ProxyPort)
	sidecarUIDString := fmt.Sprintf("%d", sidecarUID)

	return []tableRule{
		{"filter", []string{"-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-m", "owner", "--uid-owner", sidecarUIDString, "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", proxyPort, "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"}},
		{"filter", []string{"-A", "OUTPUT", "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"}},

		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", sidecarUIDString, "-j", "RETURN"}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", proxyPort}},
		{"nat", []string{"-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", proxyPort}},
	}
}

// SetupIPTables configures iptables rules for network isolation:
//   - All outbound TCP is rejected by default.
//   - Traffic from the sidecar UID is exempted.
//   - The proxy port (127.0.0.1:3128) is allowed for the main container.
//   - Established/related packets pass through.
//   - Port 80/443 is transparently redirected to the proxy port.
//
// Requires CAP_NET_ADMIN.
func SetupIPTables() error {
	return SetupIPTablesForUID(CurrentUID())
}

// SetupIPTablesForUID configures iptables rules and exempts sidecarUID.
func SetupIPTablesForUID(sidecarUID int) error {
	for _, rule := range iptablesRules(sidecarUID) {
		args := append([]string{"-t", rule.table}, rule.args...)
		cmdName, cmdArgs := iptablesCommand(os.Geteuid(), args)
		cmd := exec.Command(cmdName, cmdArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s %v: %w\noutput: %s", cmdName, cmdArgs, err, out)
		}
	}
	return nil
}

func iptablesCommand(euid int, args []string) (string, []string) {
	if euid == 0 {
		return "iptables", args
	}
	return "sudo", append([]string{"iptables"}, args...)
}

// GenerateIPTablesRestore returns a string in iptables-save/iptables-restore
// format representing the same rules that SetupIPTables would apply.
// Pipe the output to iptables-restore or write it to a file for later use.
func GenerateIPTablesRestore() string {
	return GenerateIPTablesRestoreForUID(CurrentUID())
}

// GenerateIPTablesRestoreForUID returns iptables-restore rules exempting sidecarUID.
func GenerateIPTablesRestoreForUID(sidecarUID int) string {
	// Collect rules grouped by table, preserving insertion order per table.
	type tableBlock struct {
		name  string
		rules []string
	}
	tableIndex := map[string]int{}
	var blocks []tableBlock

	for _, r := range iptablesRules(sidecarUID) {
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
