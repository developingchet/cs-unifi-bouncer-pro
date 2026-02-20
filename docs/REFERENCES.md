# External References

Relevant documentation and specifications referenced during development.

## CrowdSec

- **CrowdSec Documentation** — https://docs.crowdsec.net
- **go-cs-bouncer (Go bouncer library)** — https://github.com/crowdsecurity/go-cs-bouncer
- **Custom bouncer development guide** — https://docs.crowdsec.net/docs/bouncers/custom
- **LAPI Decision Stream API** — https://crowdsecurity.github.io/cs-api-doc/#operation/getDecisionsStream
- **cscli bouncers reference** — https://docs.crowdsec.net/docs/cscli/cscli_bouncers

## Ubiquiti / UniFi

- **UniFi Network API (community documentation)** — https://ubntwiki.com/products/software/unifi-controller/api
- **UniFi Developer Portal** — https://developer.ui.com
- **UniFi Network Application release notes** — https://community.ui.com/releases

## Go Standard Library

- **net/netip** — https://pkg.go.dev/net/netip (canonical IP types, private range checking)
- **net/http** — https://pkg.go.dev/net/http
- **crypto/tls** — https://pkg.go.dev/crypto/tls
- **text/template** — https://pkg.go.dev/text/template (firewall object naming)
- **database/sql** — not used; bbolt preferred for embedded ACID storage

## Go Dependencies

- **zerolog (structured logging)** — https://github.com/rs/zerolog
- **cobra (CLI framework)** — https://github.com/spf13/cobra
- **koanf (configuration)** — https://github.com/knadh/koanf
- **bbolt (embedded database)** — https://github.com/etcd-io/bbolt
- **msgpack (serialisation)** — https://github.com/vmihailenco/msgpack
- **prometheus/client_golang** — https://github.com/prometheus/client_golang
- **golang.org/x/sync (errgroup)** — https://pkg.go.dev/golang.org/x/sync/errgroup

## Container Security

- **Distroless base images** — https://github.com/GoogleContainerTools/distroless
- **gcr.io/distroless/static-debian12** — https://github.com/GoogleContainerTools/distroless/blob/main/base/README.md
- **Cosign (keyless image signing)** — https://github.com/sigstore/cosign
- **CycloneDX SBOM specification** — https://cyclonedx.org/specification/overview/

## IP Address Range RFCs

- **RFC 1918** — Address Allocation for Private Internets (10.x, 172.16–31.x, 192.168.x) — https://datatracker.ietf.org/doc/html/rfc1918
- **RFC 1122** — Requirements for Internet Hosts (loopback 127.0.0.0/8) — https://datatracker.ietf.org/doc/html/rfc1122
- **RFC 3927** — Dynamic Configuration of IPv4 Link-Local Addresses (169.254.0.0/16) — https://datatracker.ietf.org/doc/html/rfc3927
- **RFC 4193** — Unique Local IPv6 Unicast Addresses (fc00::/7) — https://datatracker.ietf.org/doc/html/rfc4193
- **RFC 4291** — IP Version 6 Addressing Architecture (::1, fe80::/10) — https://datatracker.ietf.org/doc/html/rfc4291
- **RFC 6598** — IANA-Reserved IPv4 Prefix for Shared Address Space / CGNAT (100.64.0.0/10) — https://datatracker.ietf.org/doc/html/rfc6598

## HTTP Specifications

- **RFC 6585** — Additional HTTP Status Codes (defines 429 Too Many Requests) — https://datatracker.ietf.org/doc/html/rfc6585
- **RFC 9110** — HTTP Semantics (supersedes RFC 7231) — https://datatracker.ietf.org/doc/html/rfc9110

## Security Standards

- **CVSS v3.1 Specification** — https://www.first.org/cvss/v3.1/specification-document
- **OCI Image Specification** — https://github.com/opencontainers/image-spec
- **Linux seccomp documentation** — https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- **Docker seccomp profiles** — https://docs.docker.com/engine/security/seccomp/

## Related Projects

- **Teifun2/cs-unifi-bouncer** — https://github.com/Teifun2/cs-unifi-bouncer (the original bouncer this project improves upon)
- **crowdsecurity/cs-firewall-bouncer** — https://github.com/crowdsecurity/cs-firewall-bouncer (iptables/nftables reference implementation)
- **cs-abuseipdb-bouncer** — https://github.com/developingchet/cs-abuseipdb-bouncer (sister project — AbuseIPDB reporting bouncer)
