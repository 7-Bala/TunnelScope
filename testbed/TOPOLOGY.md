# Testbed Topology

```
  net-a (10.10.1.0/24)                          net-b (10.10.2.0/24)
  ┌─────────────┐                                ┌─────────────┐
  │ alice       │                                │ bob         │
  │ 10.10.1.10  │──┐                          ┌──│ 10.10.2.10  │
  │ (classical) │  │                          │  │ (classical) │
  └─────────────┘  │      ┌──────────────┐    │  └─────────────┘
                    ├──────│    router    │────┤
  ┌─────────────┐   │      │ 10.10.1.1 /  │    │  ┌─────────────┐
  │ alice-pq    │───┘      │ 10.10.2.1    │    └──│ bob-pq      │
  │ 10.10.1.20  │          │ IP forwarding│       │ 10.10.2.20  │
  │ (strongSwan │          │ + tcpdump    │       │ (strongSwan │
  │  6.0.2, ML) │          │ vantage      │       │  6.0.2, ML) │
  └─────────────┘          └──────────────┘       └─────────────┘
```

## Why a router, not a direct link

`alice`/`alice-pq` and `bob`/`bob-pq` are on **separate Docker bridge networks** and can only reach
each other by routing through `router`. This is deliberate: `router` runs no strongSwan, holds no
keys, has no IPsec configuration of any kind, and its only job is `net.ipv4.ip_forward=1` plus
`tcpdump`. Whatever `router` captures is **exactly** what a genuine third-party passive observer
(vantage point **T0** in the project's tier model — `research/06-DISCOVER-gaps-and-posture.md`)
would see on the wire: no shortcut, no endpoint-side capture standing in for a path tap.

Capturing on the endpoints themselves (`alice`/`bob`) would still show identical ESP bytes, but
would not be a defensible T0 claim — an endpoint always has a plausible route to more evidence than
a true path observer. The router topology removes that ambiguity structurally rather than by
promise.

## Vantage-tier mapping used by the experiment scripts

| Tier | Source | Used by |
|---|---|---|
| **T0** (passive, path-only) | `router`'s `tcpdump -i eth0` capture | All four experiments' primary evidence |
| **T2** (endpoint telemetry) | `swanctl --list-sas`, `ip xfrm state` on alice/bob | Ground truth for every experiment — never the analyzer's own inference (no circular validation) |

## IP forwarding note

`router`'s two interfaces sit on two different `/24`s; `ip_forward=1` is subnet-level, so it routes
between `net-a` and `net-b` for **any** host in either range without per-host configuration — which
is why `alice-pq`/`bob-pq` could be added on the same two networks (different IPs) and reuse `router`
unchanged.

## Single-interface capture (not `-i any`)

`tcpdump` on `router` listens on `eth0` (the `net-a`/alice-facing interface) only, not the `any`
pseudo-interface. A forwarded packet crosses `eth0` **exactly once** in either direction (as
ingress-from-alice or egress-to-alice); `-i any` was tried first and **double-counted every packet**
(saw 264 ESP frames where `swanctl` reported 132 sent), because Linux's `any` capture surfaces a
forwarded packet on both the ingress and egress real interface. See `scripts/run_arm.sh` for the
inline note where this was fixed.
