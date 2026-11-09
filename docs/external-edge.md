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
python3 tests/edge_modules.py
```

The playbook reconciles one A record with proxying disabled. It refuses conflicting CNAME/AAAA records or multiple A records. It issues a separate certificate lineage, adds an ownership-marked nginx vhost and a renewal hook that reloads nginx only for that lineage. Existing nginx paths without the ownership marker are not overwritten. Subscription and HTTP redirect requests are not access-logged, so subscription IDs are not written to request logs.

The new HTTPS vhost forwards `/sub/` to the loopback subscription listener; all other paths go to the loopback Headscale listener. The panel admin/API listener remains private and is reached through SSH. Configure Headscale with its public HTTPS `server_url` while disabling backend TLS. If configuring `trusted_proxies`, use the actual proxy peer seen by the container; a host-nginx connection through a Docker publication may arrive from the host bridge gateway rather than loopback. The vhost replaces client-supplied IP headers with the connection's peer address and supports the custom POST upgrade used by Tailscale Control Protocol.

## Optional existing SNI frontend

Some installations already terminate public TCP 443 at a separate nginx stream/SNI frontend. A new HTTPS vhost on the host nginx is insufficient if that frontend sends unknown names elsewhere. When explicitly authorized, supply these additional private variables:

```yaml
external_edge_stream_config: /opt/existing-front/nginx.conf
external_edge_stream_container: existing-front
external_edge_stream_map: tls_backend
external_edge_stream_backend: 127.0.0.1:443
```

The adapter locates exactly one `map $ssl_preread_server_name $tls_backend` and inserts only the requested hostname before its existing default. It preserves every other entry, other maps and the default route, and refuses conflicting or ambiguous entries. It writes in place so a single-file Docker bind mount keeps its inode, preserves a restricted original backup, runs `nginx -t`, then gracefully reloads nginx inside that container. It does not recreate the container. A failed validation restores the original file without reloading the invalid configuration.

Private audit artifacts under `.local/live` record existing container identities, running-process IDs, nginx configuration hashes and public certificate hashes. Newly added containers are allowed; existing running workloads must keep their processes. Containers already stopped or restarting are recorded but their changing start timestamps are not treated as caused by the edge deployment. Audit-file updates are bookkeeping and do not mark an unchanged deployment as changed.

Verify DNS through a public resolver and validate TLS from outside the hosting LAN; NAT reflection can take a different route. A valid certificate with HTTP 502 means the edge is available but its backend is not ready. Once Headscale is running, verify `/health` and enroll a real mesh node. Check existing public sites before and after any optional SNI change. The offline module tests cover preserved map contents, idempotence, conflicting-route refusal, bind-mount inode preservation, check mode and rollback on failed nginx validation.
