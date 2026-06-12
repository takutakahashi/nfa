package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/takutakahashi/nfa/pkg/policy"
	"gopkg.in/yaml.v3"
)

// Config is the top-level nfa configuration loaded from a YAML file.
type Config struct {
	Filter         FilterConfig `yaml:"filter"`
	DeferredPolicy bool         `yaml:"deferredPolicy"`
}

// FilterConfig defines the domain filter policy.
type FilterConfig struct {
	// Mode is "allowlist", "denylist", or "count".
	// allowlist: only listed domains are permitted; all others are blocked.
	// denylist:  listed domains are blocked; all others are permitted.
	// Defaults to "denylist" when omitted.
	Mode string `yaml:"mode"`

	// CountMode enables count-only mode: domains that would be blocked are
	// recorded in the denied list but traffic is not actually rejected.
	CountMode bool `yaml:"countMode"`

	// Domains is the list of domain patterns for the chosen mode.
	// Supports leading wildcard (*.example.com) and middle wildcard (prefix.*.example.com).
	Domains []string `yaml:"domains"`
}

// Load reads a YAML config file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

// FilePolicyStore persists policy updates to a YAML config file.
type FilePolicyStore struct {
	Path string
}

// NewFilePolicyStore creates a file-backed policy store.
func NewFilePolicyStore(path string) *FilePolicyStore {
	return &FilePolicyStore{Path: path}
}

// Save writes the policy into the file's filter section, preserving other config fields.
func (s *FilePolicyStore) Save(pol policy.Policy) error {
	cfg := Config{}
	if data, err := os.ReadFile(s.Path); err == nil {
		info, err := os.Stat(s.Path)
		if err != nil {
			return fmt.Errorf("stat config %s: %w", s.Path, err)
		}
		if info.Mode().Perm()&0o222 == 0 {
			return fmt.Errorf("config %s is read-only", s.Path)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parsing config %s: %w", s.Path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading config %s: %w", s.Path, err)
	}

	cfg.Filter.CountMode = pol.CountMode
	switch {
	case len(pol.Allowed) > 0:
		cfg.Filter.Mode = "allowlist"
		cfg.Filter.Domains = pol.Allowed
	case len(pol.Denied) > 0:
		cfg.Filter.Mode = "denylist"
		cfg.Filter.Domains = pol.Denied
	default:
		cfg.Filter.Mode = "allowlist"
		cfg.Filter.Domains = []string{}
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("marshaling config %s: %w", s.Path, err)
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return fmt.Errorf("creating config dir %s: %w", filepath.Dir(s.Path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".nfa-policy-*.yaml")
	if err != nil {
		return fmt.Errorf("creating temp config %s: %w", s.Path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) //nolint:errcheck

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp config %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp config %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp config %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		return fmt.Errorf("replacing config %s: %w", s.Path, err)
	}
	return nil
}

// IsAllowlist returns true when Mode is "allowlist".
func (f *FilterConfig) IsAllowlist() bool {
	return f.Mode == "allowlist"
}

// IsCountMode returns true when CountMode is set.
func (f *FilterConfig) IsCountMode() bool {
	return f.CountMode
}
