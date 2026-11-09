# Ansible deployment

This deployment provisions the Headscale network, 3x-ui control node, subscription HTTPS gateway, exit nodes and ingress nodes. It keeps generated credentials and certificates between runs and discovers exit mesh addresses before rendering ingress routes.

Production targets are Debian hosts reached over SSH. The local inventory deploys isolated containers through the controller's existing Podman connection, without installing host packages or changing its system services. Local resource names use the deployment ID so this deployment can coexist with the separate `tests/stand.py` stand.

## Install and run locally

Run these commands from the repository root. Use Python 3.13 for the tested, pinned Ansible runtime. The controller also needs OpenSSL, a running Podman Linux machine and network access.

```sh
python3.13 -m venv .local/ansible-venv
.local/ansible-venv/bin/pip install -r deploy/ansible/requirements.txt
ANSIBLE_HOME="$PWD/.local/ansible-home" .local/ansible-venv/bin/ansible-galaxy collection install -r deploy/ansible/requirements.yml -p .local/ansible-collections
./scripts/build.sh
python3 tests/ansible.py run
```

The requirements pin Ansible Core and the `containers.podman` collection. `scripts/ansible.sh` selects the local virtual environment and confines Ansible configuration, collections and temporary files to the workspace. The local inventory uses already-built images; `scripts/build.sh` includes the subscription gateway image.

To exercise image staging/building through Ansible on the local Podman service, use `./scripts/ansible.sh -i deploy/ansible/inventory.local.yml deploy/ansible/build.yml --limit headscale -e build_images=true`. Production `site.yml` performs this stage automatically. Use `build_images: false` when supplying prebuilt image references from a registry.

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

## Deploy to Debian over SSH

Copy `inventory.example.yml` to a separate inventory, replace the documentation IP addresses with reachable Debian hosts, configure SSH access and set the real public Headscale/ingress DNS names. Keep the example `vless` child group and place shared overrides there; host-specific values belong on each inventory host. The `deployment_defaults` role supplies lower-priority defaults and resolves them before provisioning.

Provide valid TLS certificates and matching keys on the controller before running. The default filenames under `.local/ansible/production/tls` are `headscale.crt` / `headscale.key`, `control.crt` / `control.key`, and one `<ingress-inventory-name>.crt` / `.key` pair per ingress, such as `in-eu.crt`. `headscale.crt` must cover the Headscale URL hostname; `control.crt` must cover `subscription_public_url` (default `https://subscriptions.example.com`); each ingress certificate must cover its configured `ingress_server_name`. Supply chains in PEM format and restrict keys to mode 0600. Preflight checks SANs, key pairing, key permissions and at least 24 hours of remaining validity. Set `headscale_ca_file` when using private PKI; an empty value selects system trust.

```sh
./scripts/ansible.sh -i deploy/ansible/inventory.production.yml deploy/ansible/site.yml --become
```

Production hosts install Podman and build the images for their own architecture by default. They need Debian package and image/download access. Use separate hosts for the example roles, since each role uses its documented public ports. The playbook does not create public DNS records, issue or renew production certificates, or change host/provider firewall rules. Permit HTTPS for Headscale/subscriptions/public ingress as appropriate, SSH for administration and UDP 41641 for mesh traversal. Exit TCP 8443 is private to the mesh and must not be exposed publicly.

For private administration, forward the remote control host's loopback listener:

```sh
ssh -L 12053:127.0.0.1:2053 deploy@CONTROL_HOST
```

Then open `http://127.0.0.1:12053`. The subscription gateway returns 404 for admin and API paths. Ingress synchronization deliberately uses HTTP on the control node's authenticated WireGuard address, with `panel.allow_http: true`; it is independent of the subscription HTTPS gateway.

## Deployment order

1. Validate inventory and prepare persistent controller secrets.
2. Prepare Podman and deployment directories on production Debian hosts.
3. Start Headscale with HTTPS, persistent database/Noise keys and role-based ACLs.
4. Create enrollment keys for each node, then start control and exits.
5. Discover exit mesh addresses and reconcile the designated 3x-ui inbound and managed clients.
6. Render ingress routes, start ingress and publish subscription HTTPS.

The local inventory hosts are `headscale`, `control`, `out-a`, `out-b` and `in`. Its deployment ID is `va`; change it before deploying a second installation on the same Podman service. The production example uses `production`. Local generated state lives under `.local/ansible-test/controller` and `.local/ansible-test/runtime`.

## Security and persistence

Generated secrets must be persistent: changing a user UUID changes its subscription identity; changing a transit UUID requires coordinated ingress/exit updates. Treat controller state and remote secret directories as credentials. Restrict their permissions, exclude them from source control and back them up with the Headscale and 3x-ui data volumes. Task output involving credentials should remain hidden with Ansible `no_log`.

Production requires DNS and certificate configuration appropriate to its public endpoints. Private certificates used by a local test must be explicitly trusted by the test clients; the local test does not prove public DNS or public certificate issuance. Headscale keys, TLS private keys and generated client UUIDs must not be regenerated on an unchanged second run.

The HTTPS gateway exposes the subscription path `/sub/` only. It runs as an independent container on the control host’s Podman bridge and forwards to 3x-ui’s subscription listener. It does not publish the 3x-ui admin UI or API. Reach administration through SSH forwarding to the control host's loopback listener, then open the forwarded local address. The production panel listener is normally port 2053; the local example uses port 22053. Ingress API synchronization uses the private mesh route rather than the public subscription gateway.

Headscale ACLs should permit ingress → exit TCP 8443 and ingress → control TCP 2053. Tagged identities must match the enrollment keys. Preserve outbound UDP and DERP connectivity for peer discovery and recovery. The subscription gateway must not forward arbitrary URLs or expose the control directory inbound.

## Reruns and changes

Rerun the same inventory and variables to reconcile configuration. Restart containers only when their image or rendered configuration changes. Preserve named state volumes across recreation, and discover mesh IPs from running node identities rather than assuming allocation order.

Run `site.yml` with the full inventory: each run collects the control/exit addresses and directory ID needed by later plays. Do not use `--limit` or skip provisioning stages for this orchestrated playbook. The optional `build.yml` can be limited to individual hosts.

To add a user, append `{email: NAME, exit: EXIT_HOST}` to `vless_users` and rerun. To add an ingress, add its inventory host, public address/SNI and TLS certificate pair, then rerun; existing accounts are advertised on the new endpoint. To add an exit for an existing account, add the exit host and change that account's `exit` value; its UUID and subscription ID remain unchanged. Containers for hosts removed from inventory are not automatically stopped, and their Headscale identities are not revoked. Decommission those hosts explicitly before retiring them from the inventory.

Update managed clients by stable email and preserve existing UUIDs. Removing an entry disables that managed account; it keeps the account for audit and preserves unrelated clients and inbounds. The module reserves the directory remark `vless-mesh-ansible-directory-v1` and a client-comment ownership marker. It refuses to take over a colliding unmanaged email. These managed accounts use unlimited traffic, no device limits and no expiry; Ansible owns their enabled state. Apply ingress changes in a controlled rollout: the current node agent restarts Xray when its user set changes, interrupting existing sessions.

Production containers use Podman's restart policy and the `podman-restart.service` boot integration. The local Podman test exercises container creation, configuration, enrollment, synchronization, subscriptions and rerun behavior. It does not verify Debian package installation, SSH transport, host firewall rules or recovery across a production host reboot. Verify those on a representative Debian host before rollout.

## Enrollment recovery

Each node receives a single-use, 24-hour Headscale enrollment key. An unchanged rerun retains that key and the persistent Tailscale identity. Normal container restarts do not require a fresh enrollment.

Automatic recovery from a lost node identity volume or a restored/replaced Headscale database is not implemented. If a node has lost its identity and its saved key is consumed, expired or absent from the current Headscale database:

1. Confirm which node lost its state; do not reset a healthy peer.
2. On the Headscale host, inspect registrations with `sudo podman exec production-headscale headscale nodes list -o json`. If an obsolete registration remains for the lost identity, remove that specific ID with `sudo podman exec production-headscale headscale nodes delete --identifier NODE_ID --force`.
3. On the controller, remove only the corresponding saved enrollment file, for example `.local/ansible/production/enrollment/out-eu.key`. Preserve user UUIDs, subscription IDs, transit UUIDs, admin credentials and healthy node volumes.
4. Rerun the same inventory. The playbook issues a new tagged key, updates the node's secret and discovers its resulting mesh address before rendering ingress.

Adjust container names and controller paths to the deployment ID and inventory hostname. When replacing the entire Headscale database, remove its obsolete saved enrollment key files for all affected nodes before redeploying. Restore database and node-state backups together where possible. Renew production TLS credentials externally, then rerun the playbook to install them; generated local test certificates are valid for seven days and are not renewed automatically.

## Verification

A completed local run, including user/ingress/exit additions and zero-change reruns, is recorded in [docs/ansible-verification.md](../../docs/ansible-verification.md).

A complete deployment test should check both exits by observed source address, direct mesh connectivity, unknown-user rejection, subscriptions that reference the public ingress, and unchanged credentials/container identities on a second Ansible run. Check ingress recovery during a control outage and exit recovery while retaining its mesh identity. Production also needs a reboot test and an external client check of its real public TLS endpoint.

See the repository [architecture guide](../../docs/architecture.md) for the data plane and accounting limits, and the generated Ansible inventory and playbook for the exact deployment variables and commands.

## Publishing images

These playbooks build images on the target hosts by default. Publishing a container registry release is a separate task. The current Dockerfiles do not assemble a complete upstream license/notice and corresponding-source bundle; see [third-party notices](../../THIRD_PARTY_NOTICES.md) before redistributing built images. The repository's Apache-2.0 license applies to its original source, not all software inside those images.
