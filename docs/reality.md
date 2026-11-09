# REALITY with XTLS Vision

`config/in-reality.yaml` adds a public VLESS TCP ingress using REALITY and the `xtls-rprx-vision` user flow. `config/in.yaml` retains the existing TLS profile. Mesh transit remains separate VLESS inside WireGuard; client REALITY keys and Vision settings are not applied to the exit connection.

REALITY uses a reachable TLS target's handshake as camouflage. The client connects to your ingress IP or DNS name but sends one of the configured `serverNames` as SNI. That SNI must be accepted by the chosen target, usually a name in its certificate SAN. It is not an arbitrary invented hostname and does not require a certificate for your ingress hostname. Choose a target supporting TLS 1.3 and HTTP/2 and verify it from the ingress network, for example with `xray tls ping <target>`.

The YAML-only extension is `listener.stream.realitySettings.private_key_file`. It references a private file containing the raw URL-base64 X25519 private key. The agent reads that file and puts `privateKey` into its protected runtime Xray JSON; it removes `private_key_file` before Xray validation. Inline private keys are rejected. Keep the secret outside source control, mode 0600, and mount it at `/run/secrets/reality-private-key`. The renderer also validates exact nonempty SNI names, target host/port, quoted hex short IDs, and TCP/RAW transport before applying a configuration.

Use `xray x25519` from the pinned node image to generate a keypair. Store the output in a private file with shell `umask 077`; do not print it into CI logs. The server uses `PrivateKey`. The matching client key is labeled `Password` by current Xray; older releases call it `PublicKey`. Keep both this client credential and subscription URLs private. Generate a separate short ID with `openssl rand -hex 8`, and replace the example value in YAML. Short IDs must be quoted, contain an even number of hex characters, and be at most 16 characters. The core also permits an empty short ID; the managed Ansible subscription workflow intentionally requires a nonempty value.

Each authorized user must have `flow: xtls-rprx-vision` in its VLESS client record, and the client must use the same flow. Existing authenticated UUID-to-exit mappings are unchanged. A client uses these settings:

| Setting | Value |
| --- | --- |
| Server address/port | The actual ingress public address and VLESS port |
| UUID | The assigned user's UUID |
| VLESS encryption | `none` |
| Flow | `xtls-rprx-vision` |
| Transport | TCP/RAW |
| Security | `reality` |
| SNI / `serverName` | One configured target-compatible name |
| Client `password` / share-link `pbk` | The X25519 client credential corresponding to that ingress key |
| `shortId` / share-link `sid` | One configured short ID |
| Fingerprint | `chrome`, `firefox`, or `safari` |

## Managed subscriptions

3x-ui v3.11 cannot override REALITY keys separately for legacy `externalProxy` entries. The Ansible panel module therefore creates one loopback-only directory inbound per REALITY ingress profile, and attaches each managed user to all of them. Each directory has its own independent private key on control; subscription metadata points to the intended ingress's client credential and short ID. Ingress private keys stay on their corresponding ingress nodes.

The module returns `inbound_ids` keyed by stable ingress inventory names (`remark`). Configure each ingress to poll its own directory ID. Adding another ingress adds another profile and subscription entry while retaining existing client UUIDs, subscription IDs and directory profiles. The module requires a homogeneous set of TLS endpoints or REALITY endpoints; mixing their different flow policies in one managed panel deployment is rejected. Unchanged TLS deployments retain their original single-directory behavior.

REALITY is not a guarantee of undetectability. Unauthenticated connections are forwarded to the configured target, which creates a port-forwarding surface. Choose targets deliberately and account for their network policy and capacity. Target reachability and compatibility are operational dependencies; `xray run -test` checks configuration syntax, not the live target's behavior. User or profile changes may restart Xray and interrupt active sessions, as with the existing TLS profile.

Official field definitions: [Project X REALITY configuration](https://xtls.github.io/en/config/transports/reality.html) and [3x-ui REALITY documentation](https://github.com/MHSanaei/3x-ui/blob/v3.11.0/docs/content/docs/en/config/reality.mdx).

Reproducible local test results and commands: [REALITY verification](reality-verification.md).
