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
