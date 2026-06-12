# nfa
network filter for agent

## Persisting policy updates

`POST /policy` updates the running proxy policy. To persist those updates to a
YAML file, start the proxy with either:

```sh
nfa proxy --config config.yaml
```

or:

```sh
nfa proxy --policy-store-file config.yaml
```

`--policy-store-file` takes precedence for persistence. When it is omitted,
`--config` is used as the persistence file if present. The runtime policy is
updated only after the policy file is written successfully.

## Sidecar UID exemption

The iptables rules exempt the nfa sidecar UID so proxy upstream connections do
not loop back into nfa. By default, `setup` and `setup-iptables` use the current
process UID:

```sh
nfa setup
nfa setup-iptables --output - --sidecar-uid 1337
```

`NETWORK_FILTER_SIDECAR_UID` can also be used. If setup runs as root but the
proxy runs as another user, pass the proxy user's UID explicitly.
