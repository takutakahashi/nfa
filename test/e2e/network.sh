#!/bin/sh
set -eux

cleanup() {
  if [ -n "${NFA_PID:-}" ]; then kill "$NFA_PID" 2>/dev/null || true; fi
  if [ -n "${DNSMASQ_PID:-}" ]; then kill "$DNSMASQ_PID" 2>/dev/null || true; fi
  ip link del nfa-dummy 2>/dev/null || true
}
trap cleanup EXIT

fail() {
  echo "E2E failure: $*" >&2
  echo "nfa log:" >&2
  sed -n '1,240p' /tmp/nfa.log >&2 || true
  echo "dnsmasq log:" >&2
  sed -n '1,240p' /tmp/dnsmasq.log >&2 || true
  exit 1
}

# A dummy interface provides real non-loopback IPv4 and IPv6 routes while
# keeping the GitHub runner and Docker daemon networking untouched.
ip link add nfa-dummy type dummy
ip addr add 192.0.2.1/24 dev nfa-dummy
ip -6 addr add 2001:db8:1::1/64 dev nfa-dummy
ip link set nfa-dummy up

dnsmasq \
  --keep-in-foreground \
  --no-resolv \
  --port=1053 \
  --listen-address=127.0.0.1 \
  --bind-interfaces \
  --address=/allowed.example/198.51.100.10 \
  --address=/tcp.example/198.51.100.11 \
  --log-queries \
  --log-facility=/tmp/dnsmasq.log &
DNSMASQ_PID=$!

nfa proxy \
  --with-setup \
  --allowed-domains allowed.example,tcp.example \
  --dns-upstream 127.0.0.1:1053 \
  >/tmp/nfa.log 2>&1 &
NFA_PID=$!

for _ in $(seq 1 100); do
  if nc -z 127.0.0.1 3129 2>/dev/null; then break; fi
  if ! kill -0 "$NFA_PID" 2>/dev/null; then fail "nfa exited during startup"; fi
  sleep 0.1
done
nc -z 127.0.0.1 3129 2>/dev/null || fail "nfa did not become ready"

run_as_app() {
  su nobody -s /bin/sh -c "$1"
}

# Both commands address external DNS servers. The successful answers prove
# that UDP and TCP port 53 were transparently redirected to nfa.
udp_answer=$(run_as_app "dig +short +time=2 +tries=1 @203.0.113.53 allowed.example A")
[ "$udp_answer" = "198.51.100.10" ] || fail "unexpected UDP DNS answer: $udp_answer"

tcp_answer=$(run_as_app "dig +tcp +short +time=2 +tries=1 @203.0.113.54 tcp.example A")
[ "$tcp_answer" = "198.51.100.11" ] || fail "unexpected TCP DNS answer: $tcp_answer"

blocked_status=$(run_as_app "dig +time=2 +tries=1 @203.0.113.55 blocked.example A" | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
[ "$blocked_status" = "REFUSED" ] || fail "blocked DNS status was $blocked_status"
if grep -q 'query.*blocked.example' /tmp/dnsmasq.log; then fail "blocked query reached upstream DNS"; fi

# A second identical lookup must be answered from nfa's cache.
run_as_app "dig +short +time=2 +tries=1 @203.0.113.56 allowed.example A" >/dev/null
allowed_queries=$(grep -c 'query.*allowed.example' /tmp/dnsmasq.log || true)
[ "$allowed_queries" -eq 1 ] || fail "cache miss: upstream saw $allowed_queries allowed.example queries"

# Sending UDP to a peer namespace must hit the default UDP REJECT rule.
udp_before=$(iptables -t filter -L OUTPUT -n -v -x | awk '/REJECT.*udp/{print $1; exit}')
run_as_app "printf test | nc -u -w 1 192.0.2.2 9999" >/dev/null 2>&1 || true
udp_after=$(iptables -t filter -L OUTPUT -n -v -x | awk '/REJECT.*udp/{print $1; exit}')
[ "$udp_after" -gt "$udp_before" ] || fail "outbound UDP did not hit REJECT"

# The peer has a valid IPv6 route; failure and a rule-counter increment prove
# rejection by nfa rather than a missing IPv6 route.
ip6_before=$(ip6tables -t filter -L OUTPUT -n -v -x | awk '/icmp6-adm-prohibited/{print $1; exit}')
run_as_app "nc -6 -z -w 1 2001:db8:1::2 9443" >/dev/null 2>&1 && fail "outbound IPv6 unexpectedly succeeded"
ip6_after=$(ip6tables -t filter -L OUTPUT -n -v -x | awk '/icmp6-adm-prohibited/{print $1; exit}')
[ "$ip6_after" -gt "$ip6_before" ] || fail "outbound IPv6 did not hit REJECT"

echo "network E2E passed"
