# Security policy

This project is in development. Security fixes target the current `main` branch; no release or long-term support policy is established yet.

## Reporting a vulnerability

Use **Security → Advisories → Report a vulnerability** on the GitHub repository when private vulnerability reporting is enabled. If that option is unavailable, open a public issue requesting a private reporting channel without including vulnerability details, credentials or a working exploit. Do not put sensitive material in ordinary issues or pull requests.

Include the affected commit, deployment mode, relevant component versions, impact and a minimal reproduction using synthetic credentials. Never attach real panel databases, enrollment keys, TLS private keys, client UUIDs, subscription URLs or the `.local/` directory.

## Deployment boundaries

- Public ingress requires TLS or a correctly configured REALITY profile. Cleartext settings in the original local stand are explicitly for testing.
- Exit listeners bind to mesh addresses. Headscale ACLs constrain which roles can communicate; administrators must also configure host/provider firewall rules.
- The public Ansible subscription gateway serves `/sub/` only. Admin access uses an SSH tunnel; ingress-to-panel HTTP travels inside authenticated WireGuard.
- Subscription IDs and VLESS UUIDs are bearer credentials. Rotate exposed credentials and remove them from history; deleting a visible file does not revoke them.
- During a control outage, cached users remain valid until their expiry or the configured stale-cache ceiling. Revocation is not instantaneous during an outage.
- The node agent restarts Xray when applying changed users/routes. Global quotas, first-use expiry and device limits are unsupported.

Keep component versions updated deliberately, retain persistent identity/database backups and test restores. See the [architecture](docs/architecture.md) and [verification scope](docs/ansible-verification.md) before a production rollout.
