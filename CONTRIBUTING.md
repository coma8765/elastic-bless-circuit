# Contributing

Start with the [architecture](docs/architecture.md) and [deployment guide](deploy/ansible/README.md). Keep changes focused and explain the resulting behavior, validation and operational impact in the pull request.

## Development

Custom node behavior belongs in the C++20 agent. YAML is the operator-facing configuration format; Python is used for tests and Ansible modules. Match the surrounding style and preserve the fail-closed routing behavior, per-node credential isolation, persistent identities and bounded user-cache lifetime.

For the Ansible tooling, create a Python 3.13 virtual environment and install the pinned dependencies described in the deployment guide. Fast validation:

```sh
.local/ansible-venv/bin/python tests/ansible_modules.py
.local/ansible-venv/bin/python tests/ansible_guards.py
./scripts/ansible.sh -i deploy/ansible/inventory.local.yml deploy/ansible/site.yml --syntax-check
./scripts/ansible.sh -i deploy/ansible/inventory.example.yml deploy/ansible/site.yml --syntax-check
```

Build and exercise the actual renderer when changing C++ behavior or image dependencies:

```sh
./scripts/build.sh
python3 tests/validate.py
```

For changes to networking, authorization, subscriptions or service lifecycle, run the live Podman checks documented in the [README](README.md). The original stand and Ansible stand use different namespaces. Run their tests sequentially: failure-injection tests intentionally restart services. Use a dedicated local environment with `/dev/net/tun`; do not run these tests against production.

The GitHub workflows separate fast checks/renderer contracts from the manually triggered full integration suite. A green static check is not evidence of multi-host deployment, internet reachability or reboot recovery.

## Submitting a change

1. Add a regression test for meaningful behavior or a failure that the change fixes.
2. Run the checks relevant to the changed code and state their results in the PR.
3. Update examples and operational documentation when configuration or behavior changes.
4. Stage only intended public files, then run `python3 scripts/check-publication.py` and `git diff --cached --check`.

Keep `.local/`, generated inventories, panel databases, TLS keys, enrollment keys, UUIDs and subscription URLs out of commits, issue reports and CI artifacts. The publication check is a guard against common mistakes, not a complete secret scanner. Report security issues using [SECURITY.md](SECURITY.md).

Contributions to the original project files are made under [Apache-2.0](LICENSE). Preserve third-party notices and do not change upstream licensing declarations.
