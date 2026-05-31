package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level nfa configuration loaded from a YAML file.
type Config struct {
	Filter         FilterConfig `yaml:"filter"`
	DeferredPolicy bool         `yaml:"deferredPolicy"`
}

// FilterConfig defines the domain filter policy.
type FilterConfig struct {
	// Mode is either "allowlist" or "denylist".
	// allowlist: only listed domains are permitted; all others are blocked.
	// denylist:  listed domains are blocked; all others are permitted.
	// Defaults to "denylist" when omitted.
	Mode string `yaml:"mode"`

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

// IsAllowlist returns true when Mode is "allowlist".
func (f *FilterConfig) IsAllowlist() bool {
	return f.Mode == "allowlist"
}
