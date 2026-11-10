# REALITY configuration and subscription verification

Verified with the pinned Xray 26.11.9 and 3x-ui 3.11.0 on 2026-11-10. The current 28-contract renderer suite and isolated panel tests passed locally on ARM64. The earlier 27-contract suite also passed against the rebuilt amd64 Docker image on a managed server through Ansible. Renderer tests use disposable containers, and panel integration uses a fresh isolated database. The original local fixtures were temporarily stopped to free compile memory, then restored with their original container identities and both authenticated routes reverified; the expanded local deployment remained running.

| Suite | Passed | Scope |
| --- | ---: | --- |
| `tests/validate.py` | 28 | Compiled ARM64 image: C++ renderer, REALITY key-file substitution, Vision flow, YAML mesh UDP port bounds, input rejection and real `xray run -test` |
| `tests/ansible_modules.py` | 19 | Certificate/panel validation, REALITY metadata, stable independent control keys, target/SNI/public-origin validation, alias inheritance/collision checks and mixed-profile rejection |
| `tests/reality_keys.py` | 11 | Persistent X25519 identities, private-file permissions, concurrent publication and key-pair consistency |
| `tests/edge_modules.py` | 30 | Owned edge routes, quoted/case-insensitive SNI collision rejection, RFC1918 backend opt-in, subscription-only routing, separate certificate/hook ownership, check mode and rollback |
| `tests/reality_panel.py` | 18 + cleanup | Actual 3x-ui APIs and generated subscriptions, public URL persistence, aliases, eight-profile exit choices, imported metadata/expiry, disabled first-use policy, revocation, migration and idempotence |
| `tests/user_routes.py --with-renderer` | 9 | Pure route validation/HMAC contracts, actual controller identity persistence and pre-write rejection, grouped disable/remove/re-add, plus compiled renderer/Xray acceptance |
| `tests/user_import.py` | 9 | Opaque state keys, seeded UUID/token preservation, exact supported emails, metadata/expiry inheritance, malformed policy rejection and actual controller reruns |
| `tests/build_staging.py` | 1 | Three roles sharing one host: initial build, unchanged reruns, source/image upgrades and missing-image recovery |
| `tests/container_overrides.py` | 2 engines | Actual Podman and Docker: DNS/hosts addition, removal and unchanged reruns using disposable containers |

The isolated panel integration verified:

1. Check mode creates no directory or account.
2. REALITY subscriptions contain the expected Vision flow, client key, short ID, SNI and fingerprint.
3. A public HTTPS subscription prefix persists across API sessions without a panel restart; unchanged and omitted-value reruns preserve the URL, accounts and directory identities.
4. Adding an alias emits two REALITY links with the same UUID, key, short ID, SNI and fingerprint, retaining the existing directory and memberships; unchanged reruns report no changes.
5. Removing an alias retires only its advertised link and preserves the physical ingress and its identities.
6. Adding an account preserves an existing account's UUID and subscription ID.
7. Adding an ingress with a different key attaches existing accounts, advertises both profiles, and preserves the first directory's ID/private key.
8. Removing an owned ingress retires only its subscription profile.
9. Migration back to TLS produces TLS links without stale REALITY parameters; unchanged reruns report no changes.
10. TLS aliases inherit the primary SNI and preserve directory identities and user memberships through addition/removal.
11. Four exit identities and two advertised ingress addresses produce eight uniquely labeled profiles in the original subscription, with distinct backend subscription IDs.
12. Removing/re-adding an exit choice retains its UUID and the base account's original subscription token.
13. Disabling the base disables all four client identities and six managed static links; no child links are exported, and an unrelated subscription remains active. The panel may retain two disabled base-native links in its output; their presence is not evidence of authorization.
14. Unrelated operator external links retain their supported fields across grouped changes, including rows with reserved-looking remarks but unowned `namePrefix` values.
15. Imported UUIDs and base subscription tokens remain unchanged while supported profile metadata and expiry persist through the real panel API.
16. Nonnegative absolute expiry is inherited by every grouped identity, including unchanged reruns.
17. Disabled negative first-use expiry remains preserved; enabling that unnormalized policy is rejected.
18. Explicitly empty imported metadata stays empty and does not trigger repeated updates.
19. The uniquely named test container and private database volume are removed.

Reproduce from the repository root after installing the deployment's pinned Ansible requirements:

```sh
CONTAINER_ENGINE=podman BUILD_IMAGES='node control' ./scripts/build.sh
python3 tests/validate.py
.local/ansible-venv/bin/python tests/ansible_modules.py
.local/ansible-venv/bin/python tests/reality_keys.py
.local/ansible-venv/bin/python tests/edge_modules.py
.local/ansible-venv/bin/python tests/build_staging.py
.local/ansible-venv/bin/python tests/reality_panel.py
.local/ansible-venv/bin/python tests/user_routes.py --with-renderer
.local/ansible-venv/bin/python tests/user_import.py
.local/ansible-venv/bin/python tests/container_overrides.py --engine podman
```

To use an already built test image, set `NODE_IMAGE` for the renderer suite or pass `--image` to the panel suite. The latter also accepts `--engine docker` for a local Docker daemon. It publishes only random loopback ports, generates all credentials in memory, and does not read credentials from existing deployments.

The override regression requires the Debian stable-slim image to be present and creates one uniquely labeled sleeping container without ports or volumes. Use `--engine docker` for a local Docker daemon, or additionally supply `--ssh-target user@host` and optionally `--ssh-port` for an explicitly selected Docker host. It verifies the real resolver/hosts files and container identity, then removes only its owned fixture. Both engines passed during PR review.

The fast quality CI runs REALITY identity, edge-module and shared-host build contracts. The real container/panel integration runs only in the manually dispatched integration workflow, where Ansible dependencies and built images are available. Raw integration logs and generated credentials are not uploaded.

This evidence proves configuration acceptance and real subscription/control behavior. The isolated panel suite does not authenticate a REALITY data-plane session to the camouflage target, test external firewall/NAT rules, or prove target compatibility. Those require a separate client-to-ingress-to-exit traffic test against the actual deployment. Default TLS behavior remains covered by the same renderer tests and the panel suite's TLS migration case.

For Docker-based renderer checks, use `CONTAINER_ENGINE=docker NODE_IMAGE=localhost/vless-node:dev python3 tests/validate.py`. The mesh-port CLI tests include the default control configuration, valid boundaries and malformed/out-of-range values.

The earlier amd64 Docker run completed all 27 tests in 34.234 seconds, including both new mesh UDP port contracts. Its private Ansible execution log is `.local/live/renderer-docker.log`. The verified rebuilt node image was subsequently transferred to the exit host; no generated credentials or server addresses are included in this report. The subsequent PR review build passed with `-Werror` and `_FORTIFY_SOURCE=2`; its validation records are under `.local/pr-validation`. These review fixes have not been redeployed to the live services.

## Live Docker rollout

A separate two-host Docker deployment was exercised through Ansible with a public Headscale HTTPS endpoint, control and ingress sharing a LAN host, and an exit behind provider NAT. The live inventory, account credentials, certificate material and raw results remain in ignored private state.

- Cloudflare DNS-only record, trusted certificate and a narrowly scoped nginx SNI route were verified from outside the LAN. Existing nginx routes, certificates and running workload identities were preserved.
- The client imported the actual 3x-ui subscription with REALITY, Vision and its configured SNI. Two independent HTTPS IP checks returned the configured exit's public address; an unknown UUID was rejected.
- Removing mesh UDP publications was tested against running Docker containers. Docker's default comparison retains extra published ports, so the deployment explicitly compares `published_ports` strictly. Inspection confirmed no managed mesh UDP bindings and no published ports on the exit container; VLESS still worked afterward.
- Ingress-to-control communication used a direct local Docker-network path. Ingress-to-exit traffic used the encrypted DERP fallback through outbound connections, requiring no provider-side inbound UDP forwarding. A direct Internet path is not claimed.
- The final unchanged Ansible run reported `changed=0` and `failed=0` for all four logical hosts; container IDs, PIDs and start times were preserved. All mesh nodes remained healthy. The edge playbook also passed an unchanged rerun.
- A live host reboot was not performed because the hosts also run existing services.

Private evidence is under `.local/live/`: `traffic-report.json`, `mesh-report.json`, `renderer-docker.log`, and the edge/deployment Ansible logs. These artifacts are excluded from publication.

The deployment was subsequently expanded with three Docker out nodes, staged before publishing their routes. No public ports were added on those out containers. The original ingress's public and LAN addresses now each advertise all four exits, producing eight distinctly named profiles in the unchanged base subscription. Local Podman clients verified every profile against two independent IP services and rejected unknown UUIDs; an external Docker client verified all four public choices. Temporary clients were removed and their absence checked. Original account identifiers, directory keys, panel settings, nginx configuration/certificates and unrelated workloads were preserved. The complete seven-host Ansible rerun and three-host bootstrap rerun both finished with zero changes and failures. Private evidence is under `.local/live/cities/`.
