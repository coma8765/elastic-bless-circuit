# Architecture and operations

This is a reference implementation with local integration tests, not a production certification. The [3x-ui upstream README](https://github.com/MHSanaei/3x-ui/blob/v3.11.0/README.md) describes the panel as intended for personal use and discourages production deployment. Evaluate that dependency and the documented limitations before an operational rollout.

## Identity and routing

The client sends a VLESS UUID. Xray authenticates it and assigns the configured email. A routing rule maps that email to a named transit outbound. Separate UUID/email pairs let a client select different exits on the same public ingress port. The transit connection uses a different UUID; exits never receive public user credentials. Ingress must never have a Freedom outbound, including as an error fallback.

Ansible's optional user `additional_exits` list groups those exit identities in the base account's existing public subscription. The base email, UUID, token and primary exit stay unchanged. Each additional configured exit gets a persistent `base--exit` email/UUID pair and a distinct private backend subscription ID derived from its owner's token. The same validated expansion supplies panel identities and ingress routes. The panel's native external-link API includes actual generated child VLESS links in the owner's subscription, with one link per identity and advertised ingress address. It preserves unrelated external links and never fetches arbitrary remote subscriptions. Disabling the base account disables its whole group; removing an additional exit disables that identity and retires its managed share links while retaining its UUID for later re-addition. This adds egress choices through existing ingress nodes without exposing the exit listeners to the Internet.

The exit address is an operator-configured mesh address, not client-controlled routing input. For Xray versions that reject numeric CGNAT plain-VLESS destinations, the renderer creates internal `transit-N.mesh.invalid` aliases, pins them to the configured mesh IP in Xray DNS, and resolves them with `UseIPv4`. These aliases do not use external DNS. Transit sockets bind `tailscale0` when mesh enrollment is enabled, so losing the mesh route cannot send them through the default interface. Exits accept traffic on their Tailscale interface only. WireGuard authenticates/encrypts the mesh and a separate VLESS credential authenticates the ingress to the exit. Rotate transit UUIDs with a coordinated ingress/exit rollout. For overlapping rotation, deploy a replacement exit and migrate routes before retiring the old exit.

## Networking boundaries

Run one node container per host, or assign unique host UDP ports when colocating. Each gets its own Tailscale state volume and Headscale hostname. On SELinux-enforcing Podman hosts, device access also requires the provided `label=disable` setting (or an equivalent custom SELinux policy); configuration/secrets remain read-only mounts. Grant NET_ADMIN and access to `/dev/net/tun` for kernel networking inside the container namespace. No host networking, host forwarding or privileged container is required. Outbound TCP/UDP is required for internet traffic and mesh traversal. Host firewall rules and Headscale policy must limit mesh access; binding an exit to its mesh IP does not replace identity ACLs.

An example Headscale policy, after enrolling nodes with the matching tags:

```json
{
  "tagOwners": {
    "tag:in": ["autogroup:admin"],
    "tag:out": ["autogroup:admin"],
    "tag:control": ["autogroup:admin"]
  },
  "acls": [
    {"action":"accept","src":["tag:in"],"dst":["tag:out:8443","tag:control:2053"]}
  ]
}
```

Adapt administrative identity/tag ownership to your Headscale users and validate the policy on your server before applying. The local stand uses an isolated bridge and untagged lab users with Headscale's default policy; it does not exercise production ACL enforcement.

Headscale outages do not necessarily interrupt established peer communication, but discovery, new enrollment and topology updates depend on it. DERP preserves connectivity when direct UDP is unavailable; monitor direct-versus-relayed paths. Do not disable fallback solely to claim P2P. The local direct-path check uses `tailscale ping --until-direct=true` for both exits.

Control's admin/API listener is reachable by authorized ingress nodes over the mesh. Admin and subscriptions should have separate HTTPS reverse proxy routes: admin authenticated/private, subscription public with unguessable per-user subscription IDs. Never expose the directory inbound as a data-plane entry point. Its `externalProxy` metadata tells subscriptions to use the real ingress public endpoints.

## Mesh UDP port alignment

`mesh.udp_port` selects the actual `tailscaled` listener from YAML and defaults to 41641. The entrypoint validates it with `node-agent mesh-port /etc/node/config.yaml` before starting the daemon. The command works for control YAML without a data-plane role and rejects nonnumeric or out-of-range ports.

When the host already runs Tailscale on UDP 41641, choose another port for the container, for example `mesh.udp_port: 41642`, and publish **41642:41642/udp**. Keep the daemon port, Docker/Podman host publication and any upstream NAT forwarding aligned. Merely publishing 41642 to an unchanged container port 41641 can collide with the host daemon's outgoing NAT state and leave peers using DERP. In Ansible, set the per-host `mesh_udp_port` and matching `mesh_udp_publish` together. Distinct colocated node containers also need distinct ports. Port alignment helps direct reachability; provider firewall/NAT behavior must still permit the resulting UDP endpoint.

## Configuration lifecycle

The agent reads YAML at startup. Restart after changing policy, certificates, Headscale enrollment or node addresses. It polls panel users independently, reusing its authenticated CSRF/session cookies and reauthenticating after errors or credential changes. Only one configured panel inbound is authoritative. UUIDs and emails must be unique; every active user must have an explicit allowed route. Unknown routes or malformed snapshots retain the prior valid set. Empty or disabled directory inbounds legitimately remove all users.

A candidate is rendered and checked by Xray before the running instance is stopped. Atomic file replacement and `fsync` protect cached state. Cache is persisted after a valid snapshot is applied, and re-rendered against the current YAML policy when the panel is unavailable. Cache contains credentials; use restrictive filesystem permissions and encrypted backups. Default maximum stale age is 24 hours; choose a smaller value if fast revocation matters more than prolonged outage availability. A cold start without any valid cache remains unready until the panel succeeds.

Xray exit causes the agent/container to exit; unexpected tailscaled exit also causes container failure. Podman restart policy recovers it. A heartbeat health check reports the running child, but does not check a listening socket, control freshness, DERP status or internet connectivity. Add external probes for a synthetic UUID through each desired exit and alerts for `panel sync unavailable`, stale cache and failed enrollment. Keep logs out of publicly accessible storage.

A user snapshot change currently restarts Xray. That closes active TCP/UDP sessions. Clients reconnect, but this is not seamless. For a larger deployment, use independent ingress instances with staggered updates, and consider a future Xray HandlerService integration for incremental user add/remove. Exit selection is deterministic: an unavailable selected exit fails closed instead of silently changing a user's egress country or IP.

## Accounting and supported policies

The distributed ingress is not a native 3x-ui managed node. Polling transports enabled status, UUID, email and absolute expiry only. Traffic counters on the directory inbound are not measurements of traffic on ingress. Global quotas, first-use expiry and device limits require an authenticated telemetry/accounting path and coordinated state; they must not be enabled in this implementation. Users with unsupported policy settings reject the candidate snapshot and log the reason. The stale-cache ceiling still applies.

## Backups and recovery

Back up `/etc/x-ui` with SQLite-consistent tooling, Headscale database/Noise keys using its documented backup procedure, each node's Tailscale state, YAML and secret files. Test restore to an isolated network. Do not clone Tailscale state into a concurrently running node. Keep a record of container image digests, configuration revisions and credential rotation dates.

For recovery: restore control/Headscale first when possible, then exits and ingress. Confirm mesh IP allocation matches YAML, check peer connectivity, run a synthetic proxy request per route and fetch the real subscription. Cache permits ingress restart during a short control outage, but does not substitute for control-plane backups.

## Source and image releases

The repository's source license does not replace upstream component licenses. See [third-party notices](../THIRD_PARTY_NOTICES.md) for the selected dependencies and the remaining notice/source-bundle work before publishing built container images. Locally building an image and publishing that image are separate release steps.
