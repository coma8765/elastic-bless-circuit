# Verified local stand

Verified on 2026-11-09 with Podman on ARM64. The three production service images run Debian GNU/Linux 13 (trixie), built from `debian:stable-slim`.

All **43 checks passed**: 21 renderer contracts, 12 live routing/control checks, 5 TLS checks, and 5 cache security/recovery checks. A separate reduced-capability/read-only-root exit startup probe also passed.

The local stand is restored and left running after failure injection. Admin: `http://127.0.0.1:12053`; credentials: `.local/stand.json` (private, Git-ignored). SOCKS: `127.0.0.1:11080` → exit A and `:11081` → exit B.

## Commands

```sh
./scripts/build.sh
python3 tests/stand.py up
python3 tests/validate.py
python3 tests/stand.py test
python3 tests/tls.py
python3 tests/stability.py
```

Run live tests sequentially. They deliberately stop/restart services and restore the stand before finishing. The renderer suite also asks the installed Xray binary to validate generated configurations.

## Results

### Renderer: 21 passed

UUID identities and route selection, transit credential separation, default deny, listener/exit address restrictions, private destination blocking, port bounds, YAML string types, expiry, Vision compatibility, pinned DNS and Tailscale interface binding.

### Real routing / control integration: 12 passed

- UUID a routed through matching mesh exit
- UUID b routed through matching mesh exit
- unknown UUID rejected
- both mesh peers reached by direct P2P
- exit VLESS listeners bind only to their mesh addresses
- internet HTTPS through two VLESS hops
- selected exit outage fails closed while the other route stays available
- control outage preserves existing forwarding
- ingress restart recovers cached users during control outage
- panel revocation propagated
- 3x-ui subscriptions contain public ingress and matching UUIDs
- exit restart preserves mesh identity and forwarding

### TLS integration: 5 passed

- public VLESS port negotiates TLSv1.2
- both client UUIDs route through their assigned exits over public TLS
- internet HTTPS succeeds through TLS ingress and mesh transit
- 3x-ui subscription advertises public TLS ingress
- original lab configuration restored and both routes verified

### Cache outage / recovery: 5 passed

- absolute user expiry is enforced locally during a panel outage
- stale cached user snapshot removes both authorizations
- corrupt cache on a cold start remains unready and fails closed
- missing cache on a cold start remains unready and fails closed
- panel restoration recovers both valid client routes

## Image IDs

| Image | Local image ID |
| --- | --- |
| `vless-node:dev` | `3e5acc24984a0804226bba2c424597990321c4702053aa53abcde71eebdbce66` |
| `vless-control:dev` | `4720ada5ef60f0542687a4b5b8829cb7c1d9469f7ba398c635b98d604e0a426f` |
| `vless-headscale:dev` | `46bff352034c9f97e60b278ea935f786297aa2abb7d39688ed08e73ad0bfed0e` |

Pinned components: Xray 26.11.9, Tailscale 1.104.5, Headscale 0.29.7 and 3x-ui 3.11.0. The panel bundles its own local Xray; the data-plane nodes use the explicitly pinned Xray binary.

## Scope

This was tested locally on ARM64, including direct peer paths on a Podman bridge and external HTTPS forwarding. Multi-host firewalls, production Headscale ACLs, certificate issuance/renewal and amd64 execution were not exercised. Production configuration needs real Headscale/panel URLs, credentials, DNS and TLS certificates. Quotas, first-use/device limits and remote traffic accounting are unsupported; user-set updates restart Xray and interrupt existing sessions. See [README](../README.md) and [architecture](architecture.md).
