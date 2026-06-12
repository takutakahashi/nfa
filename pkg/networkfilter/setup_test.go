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
