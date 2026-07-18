package networkfilter

import (
	"strings"
	"testing"
)

func TestGenerateIPTablesRestoreDoesNotBypassPrivateCIDRs(t *testing.T) {
	restore := GenerateIPTablesRestore()
	privateCIDRs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, cidr := range privateCIDRs {
		if strings.Contains(restore, cidr) {
			t.Fatalf("GenerateIPTablesRestore() contains private CIDR bypass %s:\n%s", cidr, restore)
		}
	}
}

func TestGenerateIPTablesRestoreIncludesDirectAllowlistChains(t *testing.T) {
	restore := GenerateIPTablesRestore()
	for _, want := range []string{
		"-N NFA_DIRECT_ALLOW",
		"-A OUTPUT -p tcp -j NFA_DIRECT_ALLOW",
		"-A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 3128",
	} {
		if !strings.Contains(restore, want) {
			t.Fatalf("GenerateIPTablesRestore() missing %q:\n%s", want, restore)
		}
	}
}

func TestDirectAllowlistCIDRs(t *testing.T) {
	got := DirectAllowlistCIDRs([]string{
		"example.com",
		"192.0.2.10",
		"192.0.2.10",
		"198.51.100.0/24",
		"*.example.com",
		"2001:db8::1",
		"2001:db8::/32",
	})
	want := []string{"192.0.2.10/32", "198.51.100.0/24"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("DirectAllowlistCIDRs() = %v, want %v", got, want)
	}
}

func TestGenerateIPTablesRestoreWithDirectAllowlist(t *testing.T) {
	restore := GenerateIPTablesRestoreWithDirectAllowlist([]string{
		"example.com", "192.0.2.10", "198.51.100.17/24", "192.0.2.10",
	})
	for _, want := range []string{
		"-A NFA_DIRECT_ALLOW -p tcp -d 192.0.2.10/32 -j ACCEPT",
		"-A NFA_DIRECT_ALLOW -p tcp -d 192.0.2.10/32 -j RETURN",
		"-A NFA_DIRECT_ALLOW -p tcp -d 198.51.100.0/24 -j ACCEPT",
		"-A NFA_DIRECT_ALLOW -p tcp -d 198.51.100.0/24 -j RETURN",
	} {
		if !strings.Contains(restore, want) {
			t.Errorf("restore rules missing %q:\n%s", want, restore)
		}
	}
	if strings.Contains(restore, "example.com") {
		t.Errorf("restore rules contain hostname entry:\n%s", restore)
	}
}

func TestAllowlistedIPRangesBypassTLSRedirectAndSNIInspection(t *testing.T) {
	restore := GenerateIPTablesRestoreWithDirectAllowlist([]string{"198.51.100.0/24"})

	jump := strings.Index(restore, "-A OUTPUT -p tcp -j NFA_DIRECT_ALLOW")
	bypass := strings.Index(restore, "-A NFA_DIRECT_ALLOW -p tcp -d 198.51.100.0/24 -j RETURN")
	tlsRedirect := strings.Index(restore, "-A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 3128")
	if jump == -1 || bypass == -1 || tlsRedirect == -1 {
		t.Fatalf("restore rules do not contain the direct bypass and TLS redirect:\n%s", restore)
	}
	if jump > tlsRedirect {
		t.Fatalf("direct allowlist jump must run before the TLS redirect:\n%s", restore)
	}
}
