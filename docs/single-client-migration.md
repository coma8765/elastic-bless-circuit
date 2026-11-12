# Rolling migration to one 3x-ui client per person

On a fresh deployment set `panel_client_mode: single`, configure REALITY and the selectors below, and run the ordinary `deploy/ansible/site.yml`. Create clients on the 3x-ui **Clients** page and select their inbound memberships there. Each allowed ingress and exit combination appears as a separate Happ profile under the client's subscription URL.

## Existing grouped deployment

Use the original private inventory and controller state directory. Keep the original account manifest, endpoint names, public addresses, exit assignments, REALITY keys and subscription origin for the conversion. Confirm you have a protected copy of this inventory and state. The state includes transit and enrollment credentials and all issued UUIDs. Pause administrative edits and other deployment runs through cutover so a rollback restores the same accounts and memberships.

Add the following settings to the shared inventory. Assign each **actual exit inventory name** a distinct integer in the range 16384–20479. Keep the assignment stable after publishing links. Provide unique ingress and exit display countries and retain each ingress's existing `ingress_subscription_exits`.

```yaml
panel_client_mode: single
vless_route_selectors:
  out-prague: 16385
  out-frankfurt: 16386
```

The migration checks normalized UUID uniqueness, old exit assignments, child ownership and client policy before changing the panel. A reported selector collision with an old primary profile can be resolved by choosing a different unused selector before publication. Supply the original expanded assignments for accounts with previously issued profiles. A deployment with individually restricted exits may require a separate policy design before conversion to per-inbound access.

### Stage ingress readers

Run from the repository root with the complete inventory. The following examples use privilege escalation for remote Debian hosts.

```sh
./scripts/ansible.sh -i /path/to/private-inventory.yml --become \
  deploy/ansible/migrate-single-client.yml -e migrate_single_clients=true
```

The playbook downloads 3x-ui's SQLite online backup over the control host's loopback interface, checks the transferred file using SQLite and records the running image ID and node YAML for each control and ingress container. Every invocation creates a new private recovery directory under `controller_state_dir/single-client-backups/`. Record the first stage directory and retain its images until verification finishes.

The playbook reads the live mesh addresses and plans the panel change in Ansible check mode to obtain the existing inbound IDs. It prepares both image types and checks their capability labels. It then updates one ingress at a time and requires a fresh directory sync from the still-running panel on each reader. Established connections on an ingress may reconnect when its container is recreated. Headscale and exits continue running.

Use an existing test account in Happ with an already downloaded profile. Before refreshing its subscription, connect through the ingress and verify the observed public IP matches the intended exit. Cover each distinct ingress and exit policy, including a same-country-only ingress. Existing grouped subscriptions continue to be published during staging.

### Cut over the panel

```sh
./scripts/ansible.sh -i /path/to/private-inventory.yml --become \
  deploy/ansible/migrate-single-client.yml -e migrate_single_clients=true \
  -e single_client_migration_phase=cutover
```

Cutover repeats the backup, membership preflight and reader checks before upgrading control. It reconciles the physical inbounds, publishes their native profiles, and removes verified generated child records. The original owner retains its client UUID and subscription token. Keep the generated private `single-client-legacy.json` with the controller state to preserve eligible previously downloaded profiles on later upgrades.

Refresh an existing subscription URL and compare its `country in -> country out` entries with the inventory. Select each route in Happ and check the observed egress. In 3x-ui create a test client attached to two inbounds, confirm both appear in its subscription, detach one, then disable the client. A fresh feed and new connections should follow those changes after the ingress polling interval. Existing connections can close as the ingress reloads the Xray configuration. When validation is complete, resume account edits and run regular `site.yml` with `migrate_single_clients` at its default of `false`.

## Interruption and recovery

A failed stage stops before panel reconciliation. Fix the failed host or preflight condition and rerun the same command. A failed cutover can be retried with the same original inventory and compatibility manifest. Preserve the first verified pre-cutover database, the pre-stage configurations, and the original image IDs across retries.

If you must revert after panel writes, freeze edits, save a separate backup of the current state and identify the last verified grouped snapshot. Stop the control container and retain its database volume for recovery. Restore the grouped snapshot as `/etc/x-ui/x-ui.db` into an empty replacement volume mounted at that path; the replacement must contain only the restored database, so stale SQLite WAL files cannot be replayed. With the original grouped inventory, restore the recorded control image and configuration against that volume. Verify the old subscription URL and a cached profile, then roll the original ingress images and configurations back one at a time if needed. Ansible's control role uses the named volume `<container_name>-db`; put the restored data in that expected volume before resuming regular deployments. Changes since the selected snapshot need to be reapplied.
