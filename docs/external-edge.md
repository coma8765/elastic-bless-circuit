# Integrating an existing HTTPS host

`deploy/ansible/external-edge.yml` adds a dedicated Headscale/subscription hostname to a host that already runs Docker, nginx and Certbot. It preserves existing applications and does not install or replace these services. Supply all real hostnames, addresses and credential paths in an ignored private inventory.

The host needs an existing production ACME account, Certbot's `dns-cloudflare` plugin and an on-host credentials file containing a Cloudflare API token with zone-read and DNS-edit access for the selected zone. The token stays on that host. The playbook will not register an ACME account or accept new terms. DNS must be **DNS-only**: [Headscale does not support Cloudflare Proxy or Tunnel](https://headscale.net/stable/ref/integration/reverse-proxy/).

An example private inventory structure, using documentation-only names and addresses:

```yaml
all:
  children:
    external_edge:
      hosts:
        edge:
          ansible_host: 192.0.2.10
          ansible_user: deploy
          ansible_become: true
          external_edge_domain: mesh.example.com
          external_edge_zone: example.com
          external_edge_ipv4: 192.0.2.10
          external_edge_cf_credentials: /etc/letsencrypt/cloudflare.ini
          external_edge_headscale_upstream: 127.0.0.1:18081
          external_edge_subscription_upstream: 127.0.0.1:2096
```

Run from the repository root after installing the Ansible dependencies:

```sh
./scripts/ansible.sh -i .local/live/edge-inventory.yml deploy/ansible/external-edge.yml
.local/ansible-venv/bin/python tests/edge_modules.py
```

The playbook reconciles one A record with proxying disabled. It refuses conflicting CNAME/AAAA records or multiple A records. It issues a separate certificate lineage, adds an ownership-marked nginx vhost and a renewal hook that reloads nginx only for that lineage. Existing nginx paths without the ownership marker are not overwritten. Subscription and HTTP redirect requests are not access-logged, so subscription IDs are not written to request logs.

By default, the HTTPS vhost forwards `/sub/` to the loopback subscription listener and all other paths to the loopback Headscale listener. The panel admin/API listener remains private and is reached through SSH. Configure Headscale with its public HTTPS `server_url` while disabling backend TLS. If configuring `trusted_proxies`, use the actual proxy peer seen by the container; a host-nginx connection through a Docker publication may arrive from the host bridge gateway rather than loopback. The vhost replaces client-supplied IP headers with the connection's peer address and supports the custom POST upgrade used by Tailscale Control Protocol.

## A separate subscription-only hostname

Set `external_edge_subscription_only: true` to add a separate subscription host alongside an existing Headscale edge. In this mode only `/sub/` is proxied; all other HTTP/HTTPS paths return 404. It does not expose the panel admin/API or forward requests to Headscale, and it adds no Headscale upgrade map to nginx. Leaving the flag unset preserves the combined edge's existing output and behavior.

Give every hostname a separate configuration file, certificate lineage, renewal hook and private audit directory. For example, these variables can go on the new host entry in a separate private inventory:

```yaml
external_edge_domain: subscriptions.example.com
external_edge_subscription_only: true
external_edge_nginx_conf: /etc/nginx/conf.d/vless-subscriptions.conf
external_edge_cert_name: vless-edge-subscriptions.example.com
external_edge_renewal_hook: /etc/letsencrypt/renewal-hooks/deploy/56-vless-subscriptions
external_edge_audit_dir: "{{ playbook_dir }}/../../.local/live/subscriptions"
external_edge_subscription_upstream: 127.0.0.1:2096
```

The playbook rejects an existing owned vhost path belonging to another hostname, a renewal hook belonging to another certificate, or a certificate lineage referenced by another vhost. These checks run before DNS or certificate changes. Do not repurpose the first edge's inventory by changing only its hostname; retain the original host's paths and create a separate inventory for the new edge.

When a public SNI frontend already exists, provide the optional stream settings below for the new hostname as well. The adapter adds only that hostname's route to the same host-nginx HTTPS listener. Update `subscription_public_url` in the main deployment inventory to generate handoff URLs on the new subscription host; existing UUIDs and subscription IDs do not need to change.

## Optional existing SNI frontend

Some installations already terminate public TCP 443 at a separate nginx stream/SNI frontend. A new HTTPS vhost on the host nginx is insufficient if that frontend sends unknown names elsewhere. When explicitly authorized, supply these additional private variables:

```yaml
external_edge_stream_config: /opt/existing-front/nginx.conf
external_edge_stream_container: existing-front
external_edge_stream_map: tls_backend
external_edge_stream_backend: 127.0.0.1:443
```

The adapter locates exactly one `map $ssl_preread_server_name $tls_backend` and inserts only the requested hostname before its existing default. It preserves every other entry, other maps and the default route, and refuses conflicting or ambiguous entries. Exact hostname comparisons ignore case and recognize quoted keys and multiline statements; an equivalent existing route is left byte-for-byte unchanged. It writes in place so a single-file Docker bind mount keeps its inode, preserves a restricted original backup, runs `nginx -t`, then gracefully reloads nginx inside that container. It does not recreate the container. A failed validation restores the original file without reloading the invalid configuration.

Private audit artifacts under `.local/live` record existing container identities, running-process IDs, nginx configuration hashes and public certificate hashes. Newly added containers are allowed; existing running workloads must keep their processes. Containers already stopped or restarting are recorded but their changing start timestamps are not treated as caused by the edge deployment. Audit-file updates are bookkeeping and do not mark an unchanged deployment as changed.

Verify DNS through a public resolver and validate TLS from outside the hosting LAN; NAT reflection can take a different route. A valid certificate with HTTP 502 means the edge is available but its backend is not ready. Once Headscale is running, verify `/health` and enroll a real mesh node. Check existing public sites before and after any optional SNI change. The offline module tests cover preserved map contents, idempotence, conflicting-route refusal, bind-mount inode preservation, check mode and rollback on failed nginx validation. Template tests also verify subscription-only routing, default combined-mode compatibility and isolation of configuration/certificate/renewal-hook ownership; these use the Jinja2/PyYAML dependencies installed with Ansible.

## REALITY passthrough on an existing public TCP 443 frontend

Use `deploy/ansible/ingress-edge.yml` when an existing nginx stream frontend should forward REALITY connections to an already running ingress. This playbook creates a DNS-only dial hostname and one raw TCP/SNI route. It does not issue a certificate, add an HTTP/HTTPS vhost, terminate TLS, recreate the ingress, or change the Headscale/subscription edges.

The DNS destination and ClientHello SNI are separate inputs. For example, a client can dial `in.example.com:443` while using `www.microsoft.com` as its configured REALITY SNI. nginx must select the route using that ClientHello SNI, not the dial hostname. Keep the ingress REALITY key, short ID, server name and Vision flow consistent with the client profile.

An example private inventory, using documentation-only values:

```yaml
all:
  children:
    ingress_edge:
      hosts:
        frontend:
          ansible_host: 192.0.2.10
          ansible_user: deploy
          ansible_become: true
          ingress_edge_domain: in.example.com
          ingress_edge_zone: example.com
          ingress_edge_ipv4: 192.0.2.10
          ingress_edge_cf_credentials: /etc/letsencrypt/cloudflare.ini
          ingress_edge_stream_config: /opt/existing-front/nginx.conf
          ingress_edge_stream_container: existing-front
          ingress_edge_stream_map: tls_backend
          ingress_edge_sni: www.microsoft.com
          ingress_edge_backend: 10.0.0.10:4333
          ingress_edge_allow_private_backend: true
          ingress_edge_audit_dir: "{{ playbook_dir }}/../../.local/live/ingress"
```

```sh
./scripts/ansible.sh -i .local/live/ingress-edge-inventory.yml deploy/ansible/ingress-edge.yml
```

Backend validation permits only `127.0.0.1` by default. Explicit `allow_private_backend: true` on the module, or `ingress_edge_allow_private_backend: true` in this playbook, additionally permits IPv4 addresses in RFC1918 ranges `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`. Ports must be in `1..65535`. Public, link-local, multicast, CGNAT and IPv6 addresses are rejected by this opt-in; Python's broader `is_private` classification is not used. An authorized LAN backend avoids changing an existing ingress publication solely to add a loopback bind.

The route is validated in check mode before DNS changes. nginx is checked before reload, the module preserves all other map entries/defaults, and the audit requires existing host-nginx configuration/certificates, container identities and running process IDs to remain unchanged. An unlisted SNI previously follows the default route; adding an explicit rule changes that SNI's destination. Confirm that existing VPN profiles do not require that same SNI on a different backend. A single SNI/port cannot select two distinct REALITY backends.

After applying the edge, advertise the dial hostname with public port 443 in the managed ingress endpoint metadata. Keep its actual listener/publication port unchanged if the frontend forwards to that existing port. Existing user UUIDs, REALITY identities and subscription IDs need not change. Verify using a real REALITY client through the public 443 endpoint; an ordinary browser TLS check against the dial hostname does not validate this protocol. Recheck the existing HTTPS sites and subscription/Headscale endpoints from outside the hosting LAN.
