FROM nfa:e2e

RUN apk add --no-cache bind-tools dnsmasq iproute2 netcat-openbsd

COPY test/e2e/network.sh /usr/local/bin/nfa-network-e2e

ENTRYPOINT ["/usr/local/bin/nfa-network-e2e"]
