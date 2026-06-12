package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/takutakahashi/nfa/pkg/config"
	"github.com/takutakahashi/nfa/pkg/networkfilter"
	"github.com/takutakahashi/nfa/pkg/policy"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run the forward proxy sidecar",
	Long: `Runs the forward proxy that enforces domain filtering.

Configuration can be provided via a YAML file (--config), environment variables,
or CLI flags. Flags take precedence over env vars; env vars take precedence over
the config file.

Filter modes:
  allowlist  Only listed domains are permitted; all others are blocked.
             An empty domain list blocks all traffic.
  denylist   Listed domains are blocked; all others are permitted. (default)
             An empty domain list allows all traffic.

Count mode (--count-mode / NETWORK_FILTER_COUNT_MODE=true):
  Rules are evaluated and would-be-blocked domains are recorded in the
  denied list, but traffic is NOT actually rejected. Useful for auditing
  what a policy would block before enforcing it.

Env vars:
  NETWORK_FILTER_ALLOWED_DOMAINS  comma-separated allowed domains (sets allowlist mode)
  NETWORK_FILTER_DENIED_DOMAINS   comma-separated denied domains  (sets denylist mode)

A single listener on port 3128 handles:
  - HTTP CONNECT tunnels  (proxy-aware HTTPS via HTTP_PROXY/HTTPS_PROXY)
  - HTTP forward requests (proxy-aware HTTP)
  - Transparent TLS       (iptables-redirected port-443, SNI-filtered)

When --deferred-policy is set, the proxy starts in passthrough mode and the
configured policy is activated only after POST /enable-policy to the control
server on port 3129 (localhost only).`,
	RunE: runProxy,
}

func init() {
	proxyCmd.Flags().String("config", "", "Path to YAML config file")
	proxyCmd.Flags().StringSlice("allowed-domains", nil,
		"Domains to allow (allowlist mode). Also via NETWORK_FILTER_ALLOWED_DOMAINS.")
	proxyCmd.Flags().StringSlice("denied-domains", nil,
		"Domains to block (denylist mode). Also via NETWORK_FILTER_DENIED_DOMAINS.")
	proxyCmd.Flags().Bool("deferred-policy", false,
		"Start in passthrough mode. Activate via POST /enable-policy on port 3129.")
	proxyCmd.Flags().Bool("count-mode", false,
		"Log would-be-blocked domains but do not reject traffic. Also via NETWORK_FILTER_COUNT_MODE.")
	proxyCmd.Flags().String("policy-store-file", "",
		"Path to YAML config file where POST /policy persists policy. Defaults to --config when set.")
}

func runProxy(cmd *cobra.Command, _ []string) error {
	// Load optional config file first (lowest precedence).
	var cfg *config.Config
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath != "" {
		var err error
		cfg, err = config.Load(cfgPath)
		if err != nil {
			return err
		}
	}

	parseDomains := func(envKey string, flagVals []string) []string {
		var out []string
		if v := os.Getenv(envKey); v != "" {
			for _, d := range strings.Split(v, ",") {
				out = append(out, strings.TrimSpace(d))
			}
		}
		return append(out, flagVals...)
	}

	allowedFlag, _ := cmd.Flags().GetStringSlice("allowed-domains")
	deniedFlag, _ := cmd.Flags().GetStringSlice("denied-domains")
	deferredFlag, _ := cmd.Flags().GetBool("deferred-policy")
	countModeFlag, _ := cmd.Flags().GetBool("count-mode")
	policyStoreFile, _ := cmd.Flags().GetString("policy-store-file")

	allowedDomains := parseDomains("NETWORK_FILTER_ALLOWED_DOMAINS", allowedFlag)
	deniedDomains := parseDomains("NETWORK_FILTER_DENIED_DOMAINS", deniedFlag)
	deferredPolicy := deferredFlag
	countMode := countModeFlag || os.Getenv("NETWORK_FILTER_COUNT_MODE") == "true"

	// Merge config file values when no CLI/env override was given.
	if cfg != nil {
		if len(allowedDomains) == 0 && len(deniedDomains) == 0 {
			if cfg.Filter.IsAllowlist() {
				allowedDomains = cfg.Filter.Domains
			} else {
				deniedDomains = cfg.Filter.Domains
			}
		}
		if !deferredPolicy {
			deferredPolicy = cfg.DeferredPolicy
		}
		if !countMode {
			countMode = cfg.Filter.IsCountMode()
		}
	}

	var filter *networkfilter.Filter
	switch {
	case len(allowedDomains) > 0:
		if countMode {
			log.Printf("[nfa] allowlist count mode: %v", allowedDomains)
			filter = networkfilter.NewCountAllowlistFilter(allowedDomains)
		} else {
			log.Printf("[nfa] allowlist mode: %v", allowedDomains)
			filter = networkfilter.NewAllowlistFilter(allowedDomains)
		}
	case len(deniedDomains) > 0:
		if countMode {
			log.Printf("[nfa] denylist count mode: %v", deniedDomains)
			filter = networkfilter.NewCountFilter(deniedDomains)
		} else {
			log.Printf("[nfa] denylist mode: %v", deniedDomains)
			filter = networkfilter.NewFilter(deniedDomains)
		}
	default:
		if countMode {
			log.Printf("[nfa] deny-all count mode (no domains specified)")
			filter = networkfilter.NewCountAllowlistFilter(nil)
		} else {
			log.Printf("[nfa] deny-all mode (no domains specified)")
			filter = networkfilter.NewAllowlistFilter(nil)
		}
	}

	if deferredPolicy {
		log.Printf("[nfa] deferred-policy: policy inactive until POST /enable-policy on port %d", networkfilter.ControlPort)
	}

	proxy := networkfilter.NewProxy(filter, !deferredPolicy)
	if policyStoreFile == "" {
		policyStoreFile = cfgPath
	}
	var policyStore policy.Store
	if policyStoreFile != "" {
		log.Printf("[nfa] policy persistence file: %s", policyStoreFile)
		policyStore = config.NewFilePolicyStore(policyStoreFile)
	}

	controlAddr := fmt.Sprintf("127.0.0.1:%d", networkfilter.ControlPort)
	controlLis, err := net.Listen("tcp", controlAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", controlAddr, err)
	}
	go func() {
		if err := networkfilter.NewControlServer(proxy, policyStore).Run(controlLis); err != nil {
			log.Printf("[nfa] control server error: %v", err)
		}
	}()

	addr := fmt.Sprintf("0.0.0.0:%d", networkfilter.ProxyPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return proxy.Run(lis)
}
