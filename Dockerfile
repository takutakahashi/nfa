FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /nfa .

FROM alpine:3.21

RUN apk add --no-cache iptables sudo \
    && addgroup -g 1337 nfa \
    && adduser -D -u 1337 -G nfa nfa \
    && echo "nfa ALL=(root) NOPASSWD: /sbin/iptables" > /etc/sudoers.d/nfa \
    && chmod 0440 /etc/sudoers.d/nfa

COPY --from=builder /nfa /usr/local/bin/nfa

USER nfa

ENTRYPOINT ["nfa"]
CMD ["proxy"]
