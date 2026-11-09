# Ansible verification

Completed on 2026-11-09T20:06:51Z using real Podman containers on the local ARM64 Linux machine, controlled from macOS. Runtime: Python 3.13.18, Ansible Core 2.19.15, containers.podman 1.18.0, Podman 6.1.4.

The complete local deployment and growth workflow passed. The machine-readable evidence is `.local/ansible-test/test-results.json`; individual playbook recaps are in that directory. These private artifacts are intentionally excluded from source control.

| Scenario | Result |
| --- | --- |
| Full deployment | Headscale HTTPS/ACLs, 3x-ui, subscription gateway, ingress and two exits running |
| Add a user | Charlie authenticated, used its assigned exit and received a valid subscription; existing UUIDs/subscription IDs stayed unchanged |
| Add an ingress | Every existing account worked through the new ingress; subscriptions advertised both public ports; original ingress reported zero deployment changes |
| Add an exit | Existing Alice B moved to out-c through both ingresses without credential changes; other routes stayed intact |
| Transport and isolation | Pinned TLS VLESS, direct mesh P2P, external HTTPS and unknown-UUID rejection passed; exit-to-control and exit-to-exit TCP denied |
| Subscription boundary | Verified HTTPS links contained both ingresses and correct TLS/SNI; public root/admin/API paths returned 404 |
| Rerun stability | Base and expanded deployments reported zero changes, with identical container IDs, start times and daemon PIDs |
| Coexistence | Original stand and unrelated containers retained their identities and start times |

The final expanded rerun:

| Inventory host | Changed | Failed | Unreachable |
| --- | ---: | ---: | ---: |
| control | 0 | 0 | 0 |
| headscale | 0 | 0 | 0 |
| in | 0 | 0 | 0 |
| in-extra | 0 | 0 | 0 |
| out-a | 0 | 0 | 0 |
| out-b | 0 | 0 | 0 |
| out-c | 0 | 0 | 0 |

Additional checks passed: 11 certificate/panel-module tests, four cleanup-ownership regression tests, local and production inventory syntax checks, and Ansible source staging/image building. The second image-build play reported zero changes. The independent panel API validation also covered disabling removed managed users, re-enabling them, and preserving unrelated panel records.

Commands:

```sh
python3 tests/ansible.py run
.local/ansible-venv/bin/python tests/ansible_modules.py
.local/ansible-venv/bin/python tests/ansible_guards.py
./scripts/ansible.sh -i deploy/ansible/inventory.local.yml deploy/ansible/build.yml --limit headscale -e build_images=true
```

The expanded stand remains running with two ingresses, three exits and three managed accounts. Admin is `http://127.0.0.1:22053`, username `mesh-admin`; its password is in `.local/ansible-test/controller/panel-password`. Complete private subscription links are in `.local/ansible-test/controller/subscriptions.json`.

To reconcile that expanded topology without reverting it:

```sh
./scripts/ansible.sh -i .local/ansible-test/expanded-inventory.json deploy/ansible/site.yml
python3 tests/ansible.py verify
```

Production SSH transport, Debian package installation/systemd boot recovery, public DNS/certificates and provider firewalls were not exercised by this local test. Certificate renewal and recovery after identity-volume loss are operator procedures documented in the [deployment guide](../deploy/ansible/README.md). User/route changes may interrupt active sessions when Xray restarts; this is not a zero-downtime claim.
