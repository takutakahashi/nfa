package networkfilter

import (
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
	h := strings.ToLower(host)
	if idx := strings.LastIndex(h, ":"); idx != -1 {
		if strings.Contains(h[idx:], ":") || !strings.Contains(h, "[") {
			h = h[:idx]
		}
	}
	h = strings.TrimSuffix(h, ".")

	for _, bypass := range bypassDomains {
		if matchDomain(h, bypass) {
			return FilterResultBypassed
		}
	}

	if f.allowlistMode {
		for _, allowed := range f.allowedDomains {
			if matchDomain(h, allowed) {
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

// IsDenied returns true when host should be blocked.
func (f *Filter) IsDenied(host string) bool {
	return f.Check(host) == FilterResultBlocked
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
