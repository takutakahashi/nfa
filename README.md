# nfa
network filter for agent

## Persisting policy updates

`POST /policy` updates the running proxy policy. To persist those updates to a
YAML file, start the proxy with either:

```sh
nfa proxy --config config.yaml
```

To apply the iptables setup and start the proxy in one command, use:

```sh
nfa proxy --with-setup --config config.yaml
```

or:

```sh
nfa proxy --policy-store-file config.yaml
```

`--policy-store-file` takes precedence for persistence. When it is omitted,
`--config` is used as the persistence file if present. The runtime policy is
updated only after the policy file is written successfully.

## Chaining to an upstream HTTP proxy

To make nfa forward allowed outbound traffic through another HTTP proxy, start
it with:

```sh
nfa proxy --upstream-proxy http://proxy.example:8080 --config config.yaml
```

The same setting is available as `NETWORK_FILTER_UPSTREAM_PROXY` or
`upstreamProxy` in the YAML config. URLs with Basic auth are supported, for
example `http://user:password@proxy.example:8080`.
