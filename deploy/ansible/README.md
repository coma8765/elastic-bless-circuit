# Ansible deployment

This deployment provisions the Headscale network, 3x-ui control node, subscription HTTPS gateway, exit nodes and ingress nodes. It keeps generated credentials and certificates between runs and discovers exit mesh addresses before rendering ingress routes.

Production targets are Debian or Ubuntu hosts reached over SSH. Set `container_engine: docker` to use rootful Docker; the default remains `podman` for existing inventories. The local inventory deploys isolated containers through the controller's existing Podman connection, without installing host packages or changing its system services. Local resource names use the deployment ID so this deployment can coexist with the separate `tests/stand.py` stand.

## Install and run locally

Run these commands from the repository root. Use Python 3.13 for the tested, pinned Ansible runtime. The controller also needs OpenSSL, a running Podman Linux machine and network access.

```sh
python3.13 -m venv .local/ansible-venv
.local/ansible-venv/bin/pip install -r deploy/ansible/requirements.txt
ANSIBLE_HOME="$PWD/.local/ansible-home" .local/ansible-venv/bin/ansible-galaxy collection install -r deploy/ansible/requirements.yml -p .local/ansible-collections
./scripts/build.sh
python3 tests/ansible.py run
```

The requirements pin Ansible Core, `containers.podman` and `community.docker`. `scripts/ansible.sh` selects the local virtual environment and confines Ansible configuration, collections and temporary files to the workspace. The local inventory uses already-built images; `scripts/build.sh` includes the subscription gateway image.

To exercise image staging/building through Ansible on the local Podman service, use `./scripts/ansible.sh -i deploy/ansible/inventory.local.yml deploy/ansible/build.yml --limit headscale,control,ingress,exits -e build_images=true`. Images are selected by the logical host role; limiting this command to `headscale` builds only its coordination image. Production `site.yml` performs this stage automatically. Use `build_images: false` when supplying prebuilt image references from a registry.

The integration runner applies the real playbook, checks TLS/VLESS routes and subscriptions, and requires an unchanged second deployment to report zero changes without replacing containers or restarting daemons. It then adds a user and a second ingress, verifies that existing UUIDs and subscription IDs still work, adds an exit and assigns an existing account to it, and repeats that expanded deployment without changes. It records results and scoped cleanup resources under `.local/ansible-test`. It does not call `tests/stand.py up`.

To apply just the base local inventory:

```sh
./scripts/ansible.sh -i deploy/ansible/inventory.local.yml deploy/ansible/site.yml
```

The local endpoints are ingress TLS `127.0.0.1:24443`, subscription HTTPS `https://127.0.0.1:22443/sub/<subscription-id>`, admin `http://127.0.0.1:22053` and Headscale HTTPS `https://127.0.0.1:22444`. The extra ingress added by the full test uses port 24444. The tests explicitly trust generated certificates; ordinary browsers and clients require the same trust configuration. User UUIDs and subscription IDs are stored in private files under `.local/ansible-test/controller/users`.

The default admin username is `mesh-admin`; its generated password is in `controller/panel-password`. `controller/subscriptions.json` contains the complete per-account HTTPS subscription links. Both are private files; do not publish them. After the growth tests, use `.local/ansible-test/expanded-inventory.json` for further Ansible reruns. Applying the base inventory would disable the added user and restore its original endpoint and routing choices.

```sh
python3 tests/ansible.py verify
python3 tests/ansible.py down
```

`verify` checks the currently deployed base or expanded stand. `down` removes only the containers, volumes and network recorded in the Ansible test manifest. Controller user credentials remain available for reuse. See enrollment recovery below when replacing state volumes or the Headscale database.

## Deploy to Debian or Ubuntu over SSH

Copy `inventory.example.yml` to a separate inventory, replace the documentation IP addresses with reachable Debian or Ubuntu hosts, configure SSH access and set the real public Headscale/ingress DNS names. Keep the example `vless` child group and place shared overrides there; host-specific values belong on each inventory host. The `deployment_defaults` role supplies lower-priority defaults and resolves them before provisioning.

Provide valid TLS certificates and matching keys on the controller before running. The default filenames under `.local/ansible/production/tls` are `headscale.crt` / `headscale.key`, `control.crt` / `control.key`, and one `<ingress-inventory-name>.crt` / `.key` pair per ingress, such as `in-eu.crt`. `headscale.crt` must cover the Headscale URL hostname; `control.crt` must cover `subscription_public_url` (default `https://subscriptions.example.com`); each ingress certificate must cover its configured `ingress_server_name`. Supply chains in PEM format and restrict keys to mode 0600. Preflight checks SANs, key pairing, key permissions and at least 24 hours of remaining validity. Set `headscale_ca_file` when using private PKI; an empty value selects system trust.

```sh
./scripts/ansible.sh -i deploy/ansible/inventory.production.yml deploy/ansible/site.yml --become
```

Production hosts use the selected rootful engine and build the images for their own architecture by default. With `container_engine: docker`, an installed Docker CLI/daemon is retained; the playbook installs the distribution `docker.io` package only when its CLI is absent. It enables `docker.service` and installs the Python Requests dependency when package installation is enabled. Podman uses `podman-restart.service`. They need Debian package and image/download access. Use separate hosts for the example roles, since each role uses its documented public ports. The playbook does not create public DNS records, issue or renew production certificates, or change host/provider firewall rules. Permit HTTPS for Headscale/subscriptions/public ingress as appropriate, SSH for administration and UDP 41641 for mesh traversal. Exit TCP 8443 is private to the mesh and must not be exposed publicly.

For private administration, forward the remote control host's loopback listener:

```sh
ssh -L 12053:127.0.0.1:2053 deploy@CONTROL_HOST
```

Then open `http://127.0.0.1:12053`. The subscription gateway returns 404 for admin and API paths. Ingress synchronization deliberately uses HTTP on the control node's authenticated WireGuard address, with `panel.allow_http: true`; it is independent of the subscription HTTPS gateway.

## Runtime selection and constrained exit hosts

Put shared settings in the example inventory's `vless.vars` mapping:

```yaml
container_engine: docker
prepare_images_by_role: true
```

`container_network` selects the private engine bridge; its default derives from the legacy `podman_network` variable so existing local inventories still work. Docker uses its local Unix socket by default (`docker_host: unix:///var/run/docker.sock`). The deployment checks daemon access, requires Docker 20.10+ or Podman 4.9+, and rejects rootless Docker for these TUN/NET_ADMIN containers. It checks an existing candidate container's ownership label before modifying it; choose another `deployment_id` when the requested name belongs to a different service. Installing dependencies does not replace an existing Docker CE installation.

With `prepare_images_by_role: true`, Headscale requires only the Headscale image, control requires its image and the optional gateway, and ingress/exits require only the common node image. Building control also builds its common node base. A small exit can use `build_images: false` and a preloaded `node_image`; the playbook then inspects/pulls only that image, not Headscale/control/gateway. Set `prepare_images_by_role: false` to retain an all-images preparation stage.

Build on a machine with the same architecture as the exit, then preload the image or push it to a private registry. For an SSH transfer, for example:

```sh
CONTAINER_ENGINE=docker BUILD_IMAGES=node ./scripts/build.sh
mkdir -p .local
umask 077
docker image save localhost/vless-node:dev | gzip > .local/vless-node.tar.gz
scp .local/vless-node.tar.gz deploy@OUT_HOST:/tmp/vless-node.tar.gz
ssh deploy@OUT_HOST 'gzip -dc /tmp/vless-node.tar.gz | sudo docker image load'
```

Configure that exit with `build_images: false` and `node_image: localhost/vless-node:dev`. The controller's architecture must match the builder only when building there; `build.yml` normally builds on the selected target host. To prepare cohosted Headscale/control images on a larger target without deploying services, run:

```sh
./scripts/ansible.sh -i PRIVATE_INVENTORY deploy/ansible/build.yml --limit headscale,control -e build_images=true --become
```

`CONTAINER_ENGINE=podman` remains supported by `scripts/build.sh`. `BUILD_IMAGES` accepts `node`, `control`, `headscale` and `gateway` as an allowlisted space-separated subset; the default builds all four service images. Docker builds preserve health-check metadata natively; Podman retains its OCI cache plus Docker-format runtime packaging.

## Existing nginx TLS edge and cohosting

For an existing nginx host, keep its public listeners and certificates under that host's ownership. The container backend can publish only loopback HTTP upstreams:

```yaml
container_engine: docker
headscale_external_tls: true
headscale_url: https://mesh.example.com
headscale_publish: ["127.0.0.1:18081:8080/tcp"]
gateway_enabled: false
subscription_public_url: https://mesh.example.com
subscription_host_port: 2096
```

Headscale then listens on container HTTP 8080 while advertising its external HTTPS URL. Its container TLS certificate copies/preflight are skipped. Disabling the gateway skips its image, TLS files and container; an existing owned gateway is removed. The 3x-ui subscription port remains bound to host loopback. No public Headscale/admin cleartext listener is needed.

The separate [external-edge.yml](external-edge.yml) playbook configures a scoped nginx vhost and certificate lineage on a host with nginx, Certbot, a Cloudflare DNS plugin/credential file and an existing ACME account. Declare an `external_edge` inventory group and explicit `external_edge_domain`, `external_edge_zone`, `external_edge_ipv4` and `external_edge_cf_credentials` values in a private inventory. It routes `/sub/` to `127.0.0.1:2096`, routes other paths to Headscale at `127.0.0.1:18081`, validates nginx before graceful reload, and keeps a private audit of unrelated workload/vhost identities. It does not expose the 3x-ui admin/API listener. Review that playbook's explicit scope before running:

```sh
./scripts/ansible.sh -i PRIVATE_INVENTORY deploy/ansible/external-edge.yml
./scripts/ansible.sh -i PRIVATE_INVENTORY deploy/ansible/site.yml --become
```

Logical inventory host names must remain distinct even when their `ansible_host` addresses are the same. Assign unique published ports to cohosted services: an nginx edge already using 443 means ingress needs a different public address or port, such as `ingress_public_port: 8443` with `ingress_publish: ["8443:443/tcp"]`. Mesh containers on one physical host also need distinct UDP ports. Set a host-specific `mesh_udp_port` (for example 41642); the default `mesh_udp_publish` maps that same port on both host and container, and node YAML passes it to tailscaled. Avoid translating a different published port to a shared internal 41641 when the host already runs Tailscale. Preserve any existing host Tailscale listener. Provider/router NAT still needs a suitable UDP path; container publication cannot create a provider-side forward. DERP remains the availability fallback when direct traversal cannot be established. The playbook does not replace unrelated nginx services, Docker containers or certificates.

For a LAN whose router caches stale DNS or lacks NAT loopback, optional per-host `container_dns_servers: ["1.1.1.1", "8.8.8.8"]` and `container_extra_hosts: {"mesh.example.com": "192.0.2.10"}` apply only inside that host's managed containers. Leave their defaults (`[]` and `{}`) to retain engine DNS behavior. A split-DNS mapping changes the connection address while keeping the original HTTPS hostname/SNI and certificate validation; it does not change host DNS or solve public WAN forwarding. Configure only the hosts that need the override.

## REALITY with Vision

The TLS profile remains the default. To select REALITY for a managed deployment, set:

```yaml
ingress_security: reality
ingress_reality_target: www.microsoft.com:443
ingress_reality_server_name: www.microsoft.com
ingress_reality_fingerprint: chrome
```

Choose and verify a reachable TLS 1.3 target with a compatible server name from the ingress network. REALITY does not require a certificate for the ingress hostname. The controller creates an independent X25519 keypair and short ID per ingress at `controller_state_dir/reality/<inventory-host>.json`, mode 0600. Those persistent files must remain private and backed up; do not regenerate them on an ordinary rerun. Only each ingress's private key is copied to its `/run/secrets/reality-private-key` file. Public client metadata is handed to the panel; the private key is not returned in module output or stored in inventory.

The panel uses one loopback-only directory profile per REALITY ingress so existing accounts can have subscription entries with different ingress client credentials/short IDs. Each agent polls its own directory ID. The managed client flow is `xtls-rprx-vision`, and unchanged user UUIDs/subscription IDs work when adding another ingress profile. One managed deployment must use either TLS or REALITY consistently; mixed TLS/REALITY ingress flow policies are rejected. See [REALITY configuration and client fields](../../docs/reality.md) for the exact schema, target constraints and test coverage.

## Deployment order

1. Validate inventory and prepare persistent controller secrets.
2. Validate the selected engine, then prepare deployment directories on production Debian/Ubuntu hosts.
3. Start Headscale with container HTTPS or a configured external TLS edge, persistent database/Noise keys and role-based ACLs.
4. Create enrollment keys for each node, then start control and exits.
5. Discover exit mesh addresses and reconcile the designated 3x-ui inbound and managed clients.
6. Render ingress routes, start ingress and publish subscription HTTPS.

The local inventory hosts are `headscale`, `control`, `out-a`, `out-b` and `in`. Its deployment ID is `va`; change it before deploying a second installation on the same Podman service. The production example uses `production`. Local generated state lives under `.local/ansible-test/controller` and `.local/ansible-test/runtime`.

## Security and persistence

Generated secrets must be persistent: changing a user UUID changes its subscription identity; changing a transit UUID requires coordinated ingress/exit updates. Treat controller state and remote secret directories as credentials. Restrict their permissions, exclude them from source control and back them up with the Headscale and 3x-ui data volumes. Task output involving credentials should remain hidden with Ansible `no_log`.

Production requires DNS and certificate configuration appropriate to its public endpoints. Private certificates used by a local test must be explicitly trusted by the test clients; the local test does not prove public DNS or public certificate issuance. Headscale keys, TLS private keys and generated client UUIDs must not be regenerated on an unchanged second run.

When enabled, the HTTPS gateway exposes the subscription path `/sub/` only. It runs as an independent container on the control host’s selected-engine bridge and forwards to 3x-ui’s subscription listener. It does not publish the 3x-ui admin UI or API. Reach administration through SSH forwarding to the control host's loopback listener, then open the forwarded local address. The production panel listener is normally port 2053; the local example uses port 22053. Ingress API synchronization uses the private mesh route rather than the public subscription gateway.

Headscale ACLs should permit ingress → exit TCP 8443 and ingress → control TCP 2053. Tagged identities must match the enrollment keys. Preserve outbound UDP and DERP connectivity for peer discovery and recovery. The subscription gateway must not forward arbitrary URLs or expose the control directory inbound.

## Reruns and changes

Rerun the same inventory and variables to reconcile configuration. Restart containers only when their image or rendered configuration changes. Preserve named state volumes across recreation, and discover mesh IPs from running node identities rather than assuming allocation order.

Run `site.yml` with the full inventory: each run collects the control/exit addresses and directory ID needed by later plays. Do not use `--limit` or skip provisioning stages for this orchestrated playbook. The optional `build.yml` can be limited to individual hosts.

To add a user, append `{email: NAME, exit: EXIT_HOST}` to `vless_users` and rerun. To add an ingress, add its inventory host and public endpoint, plus the TLS certificate pair or REALITY target settings, then rerun; existing accounts are advertised on the new endpoint. To add an exit for an existing account, add the exit host and change that account's `exit` value; its UUID and subscription ID remain unchanged. Containers for hosts removed from inventory are not automatically stopped, and their Headscale identities are not revoked. Decommission those hosts explicitly before retiring them from the inventory.

Update managed clients by stable email and preserve existing UUIDs. Removing an entry disables that managed account; it keeps the account for audit and preserves unrelated clients and inbounds. The module reserves the directory remark `vless-mesh-ansible-directory-v1` and a client-comment ownership marker. It refuses to take over a colliding unmanaged email. These managed accounts use unlimited traffic, no device limits and no expiry; Ansible owns their enabled state. Apply ingress changes in a controlled rollout: the current node agent restarts Xray when its user set changes, interrupting existing sessions.

Production containers use the selected engine's restart policy. Docker enables its daemon at boot; Podman enables `podman-restart.service`. The local Podman test exercises container creation, configuration, enrollment, synchronization, subscriptions and rerun behavior. It does not verify Debian package installation, SSH transport, host firewall rules or recovery across a production host reboot. Verify those on a representative Debian host before rollout.

## Enrollment recovery

Each node receives a single-use, 24-hour Headscale enrollment key. An unchanged rerun retains that key and the persistent Tailscale identity. Normal container restarts do not require a fresh enrollment.

Automatic recovery from a lost node identity volume or a restored/replaced Headscale database is not implemented. If a node has lost its identity and its saved key is consumed, expired or absent from the current Headscale database:

1. Confirm which node lost its state; do not reset a healthy peer.
2. On the Headscale host, inspect registrations with `sudo docker exec production-headscale headscale nodes list -o json`. If an obsolete registration remains for the lost identity, remove that specific ID with `sudo docker exec production-headscale headscale nodes delete --identifier NODE_ID --force`.
3. On the controller, remove only the corresponding saved enrollment file, for example `.local/ansible/production/enrollment/out-eu.key`. Preserve user UUIDs, subscription IDs, transit UUIDs, admin credentials and healthy node volumes.
4. Rerun the same inventory. The playbook issues a new tagged key, updates the node's secret and discovers its resulting mesh address before rendering ingress.

Use `podman` instead of `docker` in these recovery commands for a Podman deployment. Adjust container names and controller paths to the deployment ID and inventory hostname. When replacing the entire Headscale database, remove its obsolete saved enrollment key files for all affected nodes before redeploying. Restore database and node-state backups together where possible. Renew production TLS credentials externally, then rerun the playbook to install them; generated local test certificates are valid for seven days and are not renewed automatically.

## Verification

A completed local run, including user/ingress/exit additions and zero-change reruns, is recorded in [docs/ansible-verification.md](../../docs/ansible-verification.md).

A complete deployment test should check both exits by observed source address, direct mesh connectivity, unknown-user rejection, subscriptions that reference the public ingress, and unchanged credentials/container identities on a second Ansible run. Check ingress recovery during a control outage and exit recovery while retaining its mesh identity. Production also needs a reboot test and an external client check of its real public TLS endpoint.

See the repository [architecture guide](../../docs/architecture.md) for the data plane and accounting limits, and the generated Ansible inventory and playbook for the exact deployment variables and commands.

## Publishing images

These playbooks build images on the target hosts by default. Publishing a container registry release is a separate task. The current Dockerfiles do not assemble a complete upstream license/notice and corresponding-source bundle; see [third-party notices](../../THIRD_PARTY_NOTICES.md) before redistributing built images. The repository's Apache-2.0 license applies to its original source, not all software inside those images.

## Mesh communication without inbound UDP ports

Set `mesh_udp_publish: []` on the deployment to avoid publishing mesh UDP ports. The nodes establish outbound control and DERP connections over HTTPS; WireGuard traffic remains encrypted between the peers while a DERP server relays it. Tailscale can still attempt direct NAT traversal through outbound-created mappings, but direct connectivity is not guaranteed behind restrictive NAT. Keep outbound HTTPS and DNS available; outbound STUN helps discover possible direct paths. This setting does not change the requested ingress VLESS listener or Headscale HTTPS endpoint. No provider-side inbound UDP forwarding is required for the relay path.
