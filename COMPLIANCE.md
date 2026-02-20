# CrowdSec Bouncer Spec Compliance

Spec: https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs/

## Classification
Network-layer remediation component (L3/L4). Enforces decisions via UniFi
controller firewall API. No HTTP request context. IP/range scope only.

## Implemented

| Spec Section | Status | Notes |
|---|---|---|
| LAPI connection | ✅ | go-cs-bouncer, SSE stream |
| /decisions/stream | ✅ | startup=true, delta mode |
| ip + range scope | ✅ | ranges stored as-is, not expanded |
| origin filtering | ✅ | CROWDSEC_ORIGINS |
| scenario filtering | ✅ | BLOCK_SCENARIO_EXCLUDE |
| Decision TTL + pruning | ✅ | bbolt + JANITOR_INTERVAL |
| ban remediation | ✅ | drop or reject via FIREWALL_BLOCK_ACTION |
| User-agent format | ✅ | crowdsec-unifi-bouncer/vX.Y.Z |
| /usage-metrics push | ✅ | LAPI_METRICS_PUSH_INTERVAL (default 30m, min 10m) |
| Startup reconcile | ✅ | FIREWALL_RECONCILE_ON_START |
| Resource cleanup on shutdown | ✅ | Final metrics push + worker drain |

## Not Applicable (N/A) — Network Layer

| Spec Section | Reason |
|---|---|
| captcha remediation | Requires L7 HTTP context. `captcha` decisions fall back to `ban`. |
| AppSec / request forwarding | No HTTP request context at firewall level. |
| Per-request decision evaluation | Decisions applied as persistent firewall state, not per-packet. |
| 403 / HTML ban response body | Network drop only; no TCP payload returned. |
| ban_template_path | Same as above. |
| captcha provider config | Same as captcha remediation. |
| live mode (/decisions) | Stream mode only; per-request LAPI lookup is architecturally incompatible. |

## Semantic Adaptations

**`processed` metric:** Spec defines this as HTTP requests evaluated. For this
bouncer, `processed` = CrowdSec decisions handled (bans applied + deletions)
within the reporting window.

**`blocked` metric:** Counts new ban decisions applied per origin+remediation_type
in the reporting window. Not active firewall rule count; not per-packet hits
(UniFi does not surface these via API).

**captcha fallback:** Any non-`ban` remediation type is treated as `ban`.

## Precedent
Same N/A classification applies to all official network-layer CrowdSec bouncers:
cs-firewall-bouncer (iptables/nftables), cs-pf-bouncer, cs-windows-firewall-bouncer.
