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

## Sidecar security model

nfa's iptables rules exempt UID `0` so the nfa sidecar can open upstream
connections without redirecting its own traffic back into the proxy. This means
the recommended pod model is:

- run the nfa sidecar as root with `CAP_NET_ADMIN`
- run the application container as a non-root UID
- do not grant the application container `CAP_NET_ADMIN`
- set `allowPrivilegeEscalation: false` for the application container
- avoid sudo and setuid-root helpers in the application container

The exempt UID is not a secret. Any process that can run as UID `0` in the
shared network namespace, or can change the iptables rules, can bypass nfa.
Keeping the app container non-root is therefore part of the enforcement
boundary.

Example application container security context:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```
