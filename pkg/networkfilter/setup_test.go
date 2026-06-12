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

func TestGenerateIPTablesRestoreForUIDUsesProvidedUID(t *testing.T) {
	restore := GenerateIPTablesRestoreForUID(1337)
	if !strings.Contains(restore, "--uid-owner 1337") {
		t.Fatalf("GenerateIPTablesRestoreForUID(1337) missing uid owner rule:\n%s", restore)
	}
	if strings.Contains(restore, "--uid-owner 0") {
		t.Fatalf("GenerateIPTablesRestoreForUID(1337) contains root uid owner rule:\n%s", restore)
	}
}

func TestParseUID(t *testing.T) {
	uid, err := ParseUID(" 1337 ")
	if err != nil {
		t.Fatalf("ParseUID: %v", err)
	}
	if uid != 1337 {
		t.Fatalf("ParseUID = %d, want 1337", uid)
	}

	for _, value := range []string{"", "abc", "-1"} {
		if _, err := ParseUID(value); err == nil {
			t.Fatalf("ParseUID(%q) succeeded, want error", value)
		}
	}
}

func TestIPTablesCommandUsesSudoWhenNotRoot(t *testing.T) {
	name, args := iptablesCommand(1337, []string{"-t", "filter", "-A", "OUTPUT"})
	if name != "sudo" {
		t.Fatalf("command = %q, want sudo", name)
	}
	want := []string{"iptables", "-t", "filter", "-A", "OUTPUT"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestIPTablesCommandUsesIPTablesWhenRoot(t *testing.T) {
	input := []string{"-t", "filter", "-A", "OUTPUT"}
	name, args := iptablesCommand(0, input)
	if name != "iptables" {
		t.Fatalf("command = %q, want iptables", name)
	}
	if strings.Join(args, " ") != strings.Join(input, " ") {
		t.Fatalf("args = %v, want %v", args, input)
	}
}
