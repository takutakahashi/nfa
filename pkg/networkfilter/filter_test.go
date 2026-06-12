package networkfilter

import "testing"

func TestFilterIsDenied(t *testing.T) {
	f := NewFilter([]string{"bad.com", "*.evil.org", "exact.io"})

	cases := []struct {
		host    string
		blocked bool
	}{
		{"bad.com", true},
		{"bad.com:80", true},
		{"good.com", false},
		{"sub.evil.org", true},
		{"evil.org", true},
		{"notevil.org", false},
		{"exact.io", true},
		{"sub.exact.io", false},
		{"", false},
	}
	for _, c := range cases {
		got := f.IsDenied(c.host)
		if got != c.blocked {
			t.Errorf("IsDenied(%q) = %v, want %v", c.host, got, c.blocked)
		}
	}
}

func TestMatchDomainMiddleWildcard(t *testing.T) {
	cases := []struct {
		host    string
		pattern string
		want    bool
	}{
		{"bedrock.us-east-1.amazonaws.com", "bedrock.*.amazonaws.com", true},
		{"bedrock.ap-northeast-1.amazonaws.com", "bedrock.*.amazonaws.com", true},
		{"bedrock-runtime.us-east-1.amazonaws.com", "bedrock-runtime.*.amazonaws.com", true},
		{"bedrock-agent.eu-west-1.amazonaws.com", "bedrock-agent.*.amazonaws.com", true},
		{"s3.us-east-1.amazonaws.com", "bedrock.*.amazonaws.com", false},
		{"notbedrock.us-east-1.amazonaws.com", "bedrock.*.amazonaws.com", false},
		{"bedrock-mantle.us-east-1.api.aws", "bedrock-mantle.*.api.aws", true},
		{"bedrock-mantle.ap-northeast-1.api.aws", "bedrock-mantle.*.api.aws", true},
		{"bedrock-mantle.eu-west-1.api.aws", "bedrock-mantle.*.api.aws", true},
		{"other.us-east-1.api.aws", "bedrock-mantle.*.api.aws", false},
	}
	for _, c := range cases {
		got := matchDomain(c.host, c.pattern)
		if got != c.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestAllowlistFilterEmptyDeniesAll(t *testing.T) {
	f := NewAllowlistFilter(nil)
	cases := []string{"example.com", "good.com", "anything.io", "sub.example.com"}
	for _, host := range cases {
		if r := f.Check(host); r != FilterResultBlocked {
			t.Errorf("NewAllowlistFilter(nil).Check(%q) = %v, want blocked", host, r)
		}
	}
}

func TestDenylistFilterEmptyAllowsAll(t *testing.T) {
	f := NewFilter(nil)
	cases := []string{"example.com", "anything.io", "sub.example.com"}
	for _, host := range cases {
		if r := f.Check(host); r != FilterResultAllowed {
			t.Errorf("NewFilter(nil).Check(%q) = %v, want allowed", host, r)
		}
	}
}

func TestFilterBlocksIPLiteralHosts(t *testing.T) {
	filters := map[string]*Filter{
		"denylist":  NewFilter(nil),
		"allowlist": NewAllowlistFilter([]string{"example.com"}),
	}
	cases := []string{
		"192.0.2.10",
		"192.0.2.10:80",
		"192.0.2.10.",
		"[2001:db8::1]",
		"[2001:db8::1]:443",
		"2001:db8::1",
	}
	for name, f := range filters {
		for _, host := range cases {
			if r := f.Check(host); r != FilterResultBlocked {
				t.Errorf("%s Check(%q) = %v, want blocked", name, host, r)
			}
		}
	}
}

func TestAllowlistFilterAllowsIPLiteralHosts(t *testing.T) {
	f := NewAllowlistFilter([]string{
		"192.0.2.10",
		"198.51.100.0/24",
		"2001:db8::/32",
		"example.com",
	})
	cases := []string{
		"192.0.2.10",
		"192.0.2.10:80",
		"198.51.100.42",
		"[2001:db8::1]",
		"[2001:db8::1]:443",
		"2001:db8::1",
	}
	for _, host := range cases {
		if r := f.Check(host); r != FilterResultAllowed {
			t.Errorf("Check(%q) = %v, want allowed", host, r)
		}
	}
}

func TestBypassDomains(t *testing.T) {
	f := NewAllowlistFilter([]string{"example.com"})
	bypassed := []string{
		"api.anthropic.com",
		"api.openai.com",
		"bedrock.us-east-1.amazonaws.com",
		"bedrock-runtime.ap-northeast-1.amazonaws.com",
		"bedrock-mantle.us-east-1.api.aws",
		"bedrock-mantle.ap-northeast-1.api.aws",
	}
	for _, host := range bypassed {
		if r := f.Check(host); r != FilterResultBypassed {
			t.Errorf("Check(%q) = %v, want bypassed", host, r)
		}
	}
}

func TestCountFilterStillReportsBlocked(t *testing.T) {
	f := NewCountFilter([]string{"bad.com", "*.evil.org"})
	if !f.IsCountMode() {
		t.Fatal("NewCountFilter: IsCountMode() = false, want true")
	}
	cases := []struct {
		host string
		want FilterResult
	}{
		{"bad.com", FilterResultBlocked},
		{"sub.evil.org", FilterResultBlocked},
		{"good.com", FilterResultAllowed},
	}
	for _, c := range cases {
		if got := f.Check(c.host); got != c.want {
			t.Errorf("Check(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestCountAllowlistFilterStillReportsBlocked(t *testing.T) {
	f := NewCountAllowlistFilter([]string{"example.com"})
	if !f.IsCountMode() {
		t.Fatal("NewCountAllowlistFilter: IsCountMode() = false, want true")
	}
	if r := f.Check("example.com"); r != FilterResultAllowed {
		t.Errorf("Check(example.com) = %v, want allowed", r)
	}
	if r := f.Check("other.com"); r != FilterResultBlocked {
		t.Errorf("Check(other.com) = %v, want blocked", r)
	}
}

func TestNormalFilterIsNotCountMode(t *testing.T) {
	if NewFilter(nil).IsCountMode() {
		t.Error("NewFilter: IsCountMode() = true, want false")
	}
	if NewAllowlistFilter(nil).IsCountMode() {
		t.Error("NewAllowlistFilter: IsCountMode() = true, want false")
	}
}

func TestFormerBypassDomainsNowBlocked(t *testing.T) {
	f := NewAllowlistFilter([]string{"example.com"})
	blocked := []string{
		"github.com",
		"api.github.com",
		"raw.githubusercontent.com",
		"registry.npmjs.org",
		"registry-1.docker.io",
		"hub.docker.com",
	}
	for _, host := range blocked {
		if r := f.Check(host); r == FilterResultBypassed {
			t.Errorf("Check(%q) = bypassed, want blocked or allowed-by-policy", host)
		}
	}
}
