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

Set the Ansible inventory's `subscription_public_url` to the public HTTPS origin, such as `https://subscriptions.example.com`, when hosting subscriptions behind a reverse proxy. The control role passes it to the panel module, which persists the complete `subURI` prefix ending in `/sub/`. Existing subscription IDs and VLESS node profiles remain unchanged. A metadata-only URL update does not restart the panel; omitting the module argument preserves a manually configured override. The reverse proxy should expose `/sub/` only, with the admin UI and API remaining private. JSON and Clash subscription paths are separate formats and are not enabled or published by this setting.

To advertise another address for the same physical ingress, keep its primary address and add host-level YAML aliases:

```yaml
ingress_advertised_aliases:
  - address: public-ingress.example.com
    port: 443
    remark: public
```

The default is an empty list. Aliases add subscription links to the existing directory; they retain its inbound ID, user memberships, UUIDs and REALITY keys. Removing an alias removes only its advertised link. Each address/port pair must be unique across primaries and aliases; alias remarks must be distinct labels of at most 64 letters, digits, dots, underscores or hyphens, starting with a letter or digit. An alias inherits the physical ingress's TLS SNI or REALITY SNI, fingerprint, public key and short ID. It does not create a node, listener, DNS record or proxy route. Configure those separately. For REALITY SNI passthrough, route the camouflage SNI (for example `www.microsoft.com`) to the physical ingress; the dial hostname in the alias does not replace that SNI.

REALITY is not a guarantee of undetectability. Unauthenticated connections are forwarded to the configured target, which creates a port-forwarding surface. Choose targets deliberately and account for their network policy and capacity. Target reachability and compatibility are operational dependencies; `xray run -test` checks configuration syntax, not the live target's behavior. User or profile changes may restart Xray and interrupt active sessions, as with the existing TLS profile.

Official field definitions: [Project X REALITY configuration](https://xtls.github.io/en/config/transports/reality.html) and [3x-ui REALITY documentation](https://github.com/MHSanaei/3x-ui/blob/v3.11.0/docs/content/docs/en/config/reality.mdx).

Reproducible local test results and commands: [REALITY verification](reality-verification.md).
