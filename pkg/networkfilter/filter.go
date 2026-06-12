package networkfilter

import (
	"net"
	"strings"
)

// bypassDomains are always allowed regardless of allowlist/denylist mode.
var bypassDomains = normalize([]string{
	"*.anthropic.com",
	"anthropic.com",
	"*.svc.cluster.local",
	"storage.googleapis.com",
	"sentry.io",
	"*.sentry.io",
	"api.openai.com",
	"bedrock.*.amazonaws.com",
	"bedrock-runtime.*.amazonaws.com",
	"bedrock-agent.*.amazonaws.com",
	"bedrock-agent-runtime.*.amazonaws.com",
	"bedrock-mantle.*.api.aws",
})

// Filter decides whether a given host should be blocked.
type Filter struct {
	deniedDomains  []string
	allowedDomains []string
	allowlistMode  bool
	countMode      bool // when true, log would-be-blocked domains but don't reject traffic
}

func normalize(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// NewFilter creates a denylist filter.
func NewFilter(deniedDomains []string) *Filter {
	return &Filter{deniedDomains: normalize(deniedDomains)}
}

// NewAllowlistFilter creates an allowlist filter: only listed domains are permitted.
func NewAllowlistFilter(allowedDomains []string) *Filter {
	return &Filter{allowedDomains: normalize(allowedDomains), allowlistMode: true}
}

// NewCountFilter creates a count-mode denylist filter: would-be-blocked domains are
// logged but traffic is not rejected.
func NewCountFilter(deniedDomains []string) *Filter {
	return &Filter{deniedDomains: normalize(deniedDomains), countMode: true}
}

// NewCountAllowlistFilter creates a count-mode allowlist filter: would-be-blocked
// domains are logged but traffic is not rejected.
func NewCountAllowlistFilter(allowedDomains []string) *Filter {
	return &Filter{allowedDomains: normalize(allowedDomains), allowlistMode: true, countMode: true}
}

// FilterResult describes the outcome of a filter check.
type FilterResult int

const (
	FilterResultAllowed  FilterResult = iota
	FilterResultBypassed
	FilterResultBlocked
)

func (r FilterResult) String() string {
	switch r {
	case FilterResultBypassed:
		return "bypassed"
	case FilterResultBlocked:
		return "blocked"
	default:
		return "allowed"
	}
}

// Check returns the FilterResult for the given host.
func (f *Filter) Check(host string) FilterResult {
	h := normalizeHost(host)
	if net.ParseIP(h) != nil {
		if f.allowlistMode {
			for _, allowed := range f.allowedDomains {
				if matchAllowedHost(h, allowed) {
					return FilterResultAllowed
				}
			}
		}
		return FilterResultBlocked
	}

	for _, bypass := range bypassDomains {
		if matchDomain(h, bypass) {
			return FilterResultBypassed
		}
	}

	if f.allowlistMode {
		for _, allowed := range f.allowedDomains {
			if matchAllowedHost(h, allowed) {
				return FilterResultAllowed
			}
		}
		return FilterResultBlocked
	}

	for _, denied := range f.deniedDomains {
		if matchDomain(h, denied) {
			return FilterResultBlocked
		}
	}
	return FilterResultAllowed
}

func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if splitHost, _, err := net.SplitHostPort(h); err == nil {
		h = splitHost
	} else if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	} else if strings.Count(h, ":") == 1 {
		if idx := strings.LastIndex(h, ":"); idx != -1 {
			h = h[:idx]
		}
	}
	return strings.TrimSuffix(h, ".")
}

func matchAllowedHost(host, pattern string) bool {
	if _, ipNet, err := net.ParseCIDR(pattern); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ipNet.Contains(ip)
		}
	}
	normalizedPattern := normalizeHost(pattern)
	if net.ParseIP(host) != nil || net.ParseIP(normalizedPattern) != nil {
		return host == normalizedPattern
	}
	return matchDomain(host, normalizedPattern)
}

// IsDenied returns true when host should be blocked.
func (f *Filter) IsDenied(host string) bool {
	return f.Check(host) == FilterResultBlocked
}

// IsAllowlistMode reports whether the filter is operating in allowlist mode.
func (f *Filter) IsAllowlistMode() bool {
	return f.allowlistMode
}

// IsCountMode reports whether the filter is in count-only mode.
// In count mode, domains that would be blocked are logged but traffic is not rejected.
func (f *Filter) IsCountMode() bool {
	return f.countMode
}

// AllowedDomains returns the domains configured in allowlist mode (empty in denylist mode).
func (f *Filter) AllowedDomains() []string {
	if f.allowedDomains == nil {
		return []string{}
	}
	return f.allowedDomains
}

// DeniedDomains returns the domains configured in denylist mode (empty in allowlist mode).
func (f *Filter) DeniedDomains() []string {
	if f.deniedDomains == nil {
		return []string{}
	}
	return f.deniedDomains
}

// matchDomain checks whether host matches the pattern.
// Supports leading wildcard (*.example.com) and middle wildcard (prefix.*.example.com).
func matchDomain(host, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return host == pattern[2:] || strings.HasSuffix(host, suffix)
	}
	if idx := strings.Index(pattern, "*."); idx > 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+1:]
		return strings.HasPrefix(host, prefix) && strings.HasSuffix(host, suffix)
	}
	return host == pattern
}
