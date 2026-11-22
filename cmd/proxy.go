package cmd

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

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
  NETWORK_FILTER_CONTROL_SOCKET   Unix domain socket path for the control API
  NETWORK_FILTER_LISTEN_ADDRESS   proxy listen address (default 127.0.0.1:3128)
  NETWORK_FILTER_UPSTREAM_PROXY   parent HTTP proxy URL for allowed outbound traffic

A single listener on port 3128 handles:
  - HTTP CONNECT tunnels  (proxy-aware HTTPS via HTTP_PROXY/HTTPS_PROXY)
  - HTTP forward requests (proxy-aware HTTP)
  - Transparent TLS       (iptables-redirected port-443, SNI-filtered)

When --deferred-policy is set, the proxy starts in passthrough mode and the
configured policy is activated only after POST /enable-policy to the control
server. By default the control server listens on port 3129 (localhost only).
When --control-socket is set, it listens only on that Unix domain socket and
does not bind port 3129.`,
	RunE: runProxy,
}

var setupIPTables = networkfilter.SetupIPTables

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
	proxyCmd.Flags().String("control-socket", "",
		"Unix domain socket path for the control API. Also via NETWORK_FILTER_CONTROL_SOCKET. When set, port 3129 is not used.")
	proxyCmd.Flags().Uint32("control-socket-mode", 0o600,
		"File mode for the control Unix socket")
	proxyCmd.Flags().String("listen-address", "",
		"TCP listen address for the forward proxy. Also via NETWORK_FILTER_LISTEN_ADDRESS. Defaults to 127.0.0.1:3128.")
	proxyCmd.Flags().String("upstream-proxy", "",
		"Parent HTTP proxy URL for allowed outbound traffic. Also via NETWORK_FILTER_UPSTREAM_PROXY.")
	proxyCmd.Flags().String("policy-store-file", "",
		"Path to YAML config file where POST /policy persists policy. Defaults to --config when set.")
	proxyCmd.Flags().Bool("with-setup", false,
		"Apply nfa iptables rules before starting the proxy. Requires CAP_NET_ADMIN.")
	proxyCmd.Flags().Bool("dns", true, "Run the policy-aware caching DNS resolver.")
	proxyCmd.Flags().String("dns-listen", "", "DNS resolver listen address (default 127.0.0.1:5353).")
	proxyCmd.Flags().StringSlice("dns-upstream", nil, "Upstream DNS server addresses (default: /etc/resolv.conf).")
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
	controlSocketFlag, _ := cmd.Flags().GetString("control-socket")
	controlSocketMode, _ := cmd.Flags().GetUint32("control-socket-mode")
	listenAddressFlag, _ := cmd.Flags().GetString("listen-address")
	upstreamProxyFlag, _ := cmd.Flags().GetString("upstream-proxy")
	policyStoreFile, _ := cmd.Flags().GetString("policy-store-file")
	withSetup, _ := cmd.Flags().GetBool("with-setup")
	dnsEnabled, _ := cmd.Flags().GetBool("dns")
	dnsListen, _ := cmd.Flags().GetString("dns-listen")
	dnsUpstreams, _ := cmd.Flags().GetStringSlice("dns-upstream")

	allowedDomains := parseDomains("NETWORK_FILTER_ALLOWED_DOMAINS", allowedFlag)
	deniedDomains := parseDomains("NETWORK_FILTER_DENIED_DOMAINS", deniedFlag)
	deferredPolicy := deferredFlag
	countMode := countModeFlag || os.Getenv("NETWORK_FILTER_COUNT_MODE") == "true"
	controlSocket := strings.TrimSpace(os.Getenv("NETWORK_FILTER_CONTROL_SOCKET"))
	if controlSocketFlag != "" {
		controlSocket = strings.TrimSpace(controlSocketFlag)
	}
	listenAddress := strings.TrimSpace(os.Getenv("NETWORK_FILTER_LISTEN_ADDRESS"))
	if listenAddressFlag != "" {
		listenAddress = strings.TrimSpace(listenAddressFlag)
	}
	if listenAddress == "" {
		listenAddress = fmt.Sprintf("127.0.0.1:%d", networkfilter.ProxyPort)
	}
	upstreamProxyURL := strings.TrimSpace(os.Getenv("NETWORK_FILTER_UPSTREAM_PROXY"))
	if upstreamProxyFlag != "" {
		upstreamProxyURL = strings.TrimSpace(upstreamProxyFlag)
	}

	// Merge config file values when no CLI/env override was given.
	if cfg != nil {
		if !cmd.Flags().Changed("dns") {
			dnsEnabled = cfg.DNS.Enabled
		}
		if dnsListen == "" {
			dnsListen = cfg.DNS.Listen
		}
		if len(dnsUpstreams) == 0 {
			dnsUpstreams = cfg.DNS.Upstreams
		}
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
		if controlSocket == "" {
			controlSocket = strings.TrimSpace(cfg.ControlSocket)
		}
		if upstreamProxyURL == "" {
			upstreamProxyURL = strings.TrimSpace(cfg.UpstreamProxy)
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
		log.Printf("[nfa] deferred-policy: policy inactive until POST /enable-policy on %s", controlEndpoint(controlSocket))
	}
	if withSetup && !dnsEnabled {
		return fmt.Errorf("--with-setup requires the DNS resolver; remove --dns=false")
	}

	if err := maybeSetupIPTables(withSetup); err != nil {
		return err
	}

	directAllowlistUpdater := networkfilter.IPTablesDirectAllowlistUpdater{}
	if len(networkfilter.DirectAllowlistCIDRs(allowedDomains)) > 0 {
		log.Printf("[nfa] configuring direct TCP allowlist: %v", networkfilter.DirectAllowlistCIDRs(allowedDomains))
		if err := directAllowlistUpdater.UpdateDirectAllowlist(allowedDomains); err != nil {
			return fmt.Errorf("direct allowlist setup failed: %w", err)
		}
	}

	proxy := networkfilter.NewProxy(filter, !deferredPolicy)
	var dnsResolver *networkfilter.DNSResolver
	if dnsEnabled {
		dnsCfg := networkfilter.DefaultDNSResolverConfig()
		dnsCfg.Listen, dnsCfg.Upstreams = dnsListen, dnsUpstreams
		if cfg != nil {
			dnsCfg.MaxEntries = cfg.DNS.MaxEntries
			if cfg.DNS.MinTTL != "" {
				d, err := time.ParseDuration(cfg.DNS.MinTTL)
				if err != nil {
					return fmt.Errorf("invalid dns.minTTL: %w", err)
				}
				dnsCfg.MinTTL = d
			}
			if cfg.DNS.MaxTTL != "" {
				d, err := time.ParseDuration(cfg.DNS.MaxTTL)
				if err != nil {
					return fmt.Errorf("invalid dns.maxTTL: %w", err)
				}
				dnsCfg.MaxTTL = d
			}
			if cfg.DNS.NegativeTTL != "" {
				d, err := time.ParseDuration(cfg.DNS.NegativeTTL)
				if err != nil {
					return fmt.Errorf("invalid dns.negativeTTL: %w", err)
				}
				dnsCfg.NegativeTTL = d
			}
		}
		var err error
		dnsResolver, err = networkfilter.NewDNSResolverForProxy(filter, !deferredPolicy, dnsCfg, proxy)
		if err != nil {
			return err
		}
		if err := dnsResolver.Start(); err != nil {
			return err
		}
	}
	if upstreamProxyURL != "" {
		if err := proxy.SetUpstreamProxy(upstreamProxyURL); err != nil {
			return err
		}
		log.Printf("[nfa] upstream proxy: %s", redactedURL(upstreamProxyURL))
	}
	if policyStoreFile == "" {
		policyStoreFile = cfgPath
	}
	var policyStore policy.Store
	if policyStoreFile != "" {
		log.Printf("[nfa] policy persistence file: %s", policyStoreFile)
		policyStore = config.NewFilePolicyStore(policyStoreFile)
	}

	controlLis, cleanupControlSocket, err := listenControl(controlSocket)
	if err != nil {
		return err
	}
	defer cleanupControlSocket()
	if controlSocket != "" {
		if err := os.Chmod(controlSocket, os.FileMode(controlSocketMode)); err != nil {
			return fmt.Errorf("chmod control socket: %w", err)
		}
	}
	go func() {
		controlServer := networkfilter.NewControlServer(proxy, policyStore)
		controlServer.SetDNSResolver(dnsResolver)
		controlServer.SetDirectAllowlistUpdater(directAllowlistUpdater)
		if err := controlServer.Run(controlLis); err != nil {
			log.Printf("[nfa] control server error: %v", err)
		}
	}()

	lis, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddress, err)
	}
	return proxy.Run(lis)
}

func maybeSetupIPTables(withSetup bool) error {
	if !withSetup {
		return nil
	}
	log.Println("[nfa] applying iptables setup before proxy start...")
	if err := setupIPTables(); err != nil {
		return fmt.Errorf("iptables setup failed: %w", err)
	}
	log.Println("[nfa] iptables setup applied successfully")
	return nil
}

func listenControl(socketPath string) (net.Listener, func(), error) {
	if socketPath == "" {
		controlAddr := fmt.Sprintf("127.0.0.1:%d", networkfilter.ControlPort)
		controlLis, err := net.Listen("tcp", controlAddr)
		if err != nil {
			return nil, func() {}, fmt.Errorf("listen %s: %w", controlAddr, err)
		}
		return controlLis, func() {}, nil
	}

	if st, err := os.Stat(socketPath); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, func() {}, fmt.Errorf("listen unix %s: path exists and is not a socket", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, func() {}, fmt.Errorf("remove stale unix socket %s: %w", socketPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, func() {}, fmt.Errorf("stat unix socket %s: %w", socketPath, err)
	}

	controlLis, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, func() {}, fmt.Errorf("listen unix %s: %w", socketPath, err)
	}
	return controlLis, func() {
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			log.Printf("[nfa] remove unix socket %s: %v", socketPath, err)
		}
	}, nil
}

func controlEndpoint(socketPath string) string {
	if socketPath != "" {
		return fmt.Sprintf("unix socket %s", socketPath)
	}
	return fmt.Sprintf("port %d", networkfilter.ControlPort)
}

func redactedURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return rawURL
	}
	u.User = url.UserPassword(u.User.Username(), "xxxxx")
	return u.String()
}
