#!/usr/bin/python
"""Idempotent 3x-ui v3.11 directory/subscription configuration.

Ownership is explicit: one reserved inbound remark and a JSON client comment.
The module never adopts, deletes or detaches an unrelated panel object.
"""
from __future__ import absolute_import, division, print_function

import copy
import base64
import re
import secrets
import http.cookiejar
import ipaddress
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import hashlib
import hmac

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: vless_panel
short_description: Reconcile the managed VLESS mesh directory in 3x-ui v3.11
options:
  url:
    description: Panel URL, including any configured base path. HTTP is allowed only on loopback.
    type: str
    required: true
  username:
    type: str
    required: true
  password:
    type: str
    required: true
  client_mode:
    type: str
    choices: [grouped, single]
    default: grouped
    description: In single mode the panel owns client lifecycle and inbound membership.
  migrate_single_clients:
    type: bool
    default: false
    description: Explicitly retire verified grouped client rows and their owned subscription links during a single-mode migration.
  defer_new_auto:
    type: bool
    default: false
    description: Publish new Auto selectors only after their gateway and ingress are ready.
  route_selectors:
    type: dict
    default: {}
    description: Stable exit inventory name to VLESS route number in the range 16384..20479.
  exit_countries:
    type: dict
    default: {}
    description: Display country for each route selector.
  users:
    description: Owned client identities for grouped mode or the identity manifest for an explicit migration.
    type: list
    elements: dict
    required: true
  ingress_endpoints:
    description: Public TLS or REALITY ingress endpoints advertised in client subscriptions.
    type: list
    elements: dict
    required: true
  directory_port:
    description: Initial directory port allocation base; existing profile ports remain stable.
    type: int
    default: 14443
  subscription_port:
    type: int
    default: 2096
  subscription_public_url:
    description: Optional HTTPS origin for advertised subscription links; omission preserves the current override.
    type: str
notes:
  - Single mode configures native directory publication. Create clients and choose their inbound memberships in the panel. Deleting a client there is permanent across topology runs.
  - The single-mode conversion requires the original expanded client manifest and a quiescent database copy. It preserves the base record, its current memberships and its subscription token.
  - subscription_owner groups child identities through native external links; child backend subscription IDs are derived from the unchanged owner token.
  - Static external-link namePrefix values beginning vless-mesh-ansible: are reserved; unrelated rows are preserved.
  - Each ingress endpoint may include aliases containing address, port, remark and optional display_country; aliases inherit its security profile and use the same directory.
  - Optional endpoint display_country and user exit_display_country produce exact country route names through owned native static external links.
  - Optional subscription_exits selects published exit identities per physical ingress; empty means all, aliases inherit, and nonempty filters require country labels.
  - In single mode an optional ingress auto_selector adds a country -> Auto entry for the gateway. Aliases inherit the selector.
  - advertise=false prepares a directory and membership without publishing its endpoints; at least one endpoint must remain advertised.
  - The inbound remark vless-mesh-ansible-directory-v1 is reserved for this module.
  - Client comments contain an ownership marker; removing it relinquishes ownership.
  - Removed managed clients are disabled globally but remain in the panel for audit.
  - Check mode authenticates and reads state, but makes no configuration changes.
'''

MANAGED = "vless-mesh-ansible/v1"
DIRECTORY = "vless-mesh-ansible-directory-v1"
LINK_PREFIX = "vless-mesh-ansible:"
ATTACH_FROM = "vlessMeshAttachFrom"


class PanelError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PanelError("panel redirects are not permitted")


class Panel:
    def __init__(self, url, username, password):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.opener = None
        self.token = None
        self.login()

    def call(self, path, data=None):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-CSRF-Token"] = self.token
        payload = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(self.url + path, data=payload, headers=headers)
        try:
            with self.opener.open(req, timeout=15) as response:
                body = response.read(16 * 1024 * 1024 + 1)
            if len(body) > 16 * 1024 * 1024:
                raise PanelError("panel response exceeds size limit")
            result = json.loads(body.decode("utf-8"))
        except (urllib.error.URLError, ValueError, OSError):
            # Never include response bodies, cookies or credentials in module output.
            raise PanelError("panel request failed: " + path.split("?")[0])
        if not isinstance(result, dict) or not result.get("success"):
            raise PanelError("panel rejected request: " + path.split("?")[0])
        return result.get("obj")

    def login(self):
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.token = None
        self.token = self.call("/csrf-token")
        if not isinstance(self.token, str) or not self.token:
            raise PanelError("panel returned an invalid CSRF token")
        self.call("/login", {"username": self.username, "password": self.password})

    def restart(self):
        try:
            self.call("/panel/api/setting/restartPanel", {})
        except PanelError as error:
            # The process can close its HTTP connection before sending a response.
            if not str(error).startswith("panel request failed:"):
                raise
        deadline = time.monotonic() + 45
        time.sleep(1)
        while time.monotonic() < deadline:
            try:
                self.login()
                return
            except PanelError:
                time.sleep(1)
        raise PanelError("panel did not become ready after restart")


def object_value(value):
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise PanelError("panel returned an invalid object")
    return value


def ownership(client):
    try:
        comment = json.loads(client.get("comment", ""))
    except (TypeError, ValueError):
        return False
    return isinstance(comment, dict) and comment.get("managed_by") == MANAGED


def comment_for(exit_name, metadata=None):
    comment = {"managed_by": MANAGED, "exit": exit_name}
    metadata = metadata or {}
    if 'comment' in metadata:
        comment['source_comment'] = metadata['comment']
    audit = {key: metadata[key] for key in ['source_email', 'source_uuid', 'original_expiry_time', 'created_at', 'updated_at'] if key in metadata}
    if audit:
        comment['source_metadata'] = audit
    return json.dumps(comment, sort_keys=True, separators=(",", ":"))


def valid_port(value):
    if value < 1 or value > 65535:
        raise PanelError("ports must be in 1..65535")
    return value


def child_subscription_id(owner_token, email):
    return hmac.new(owner_token.encode(), b'vless-mesh-child-subscription-v1\x00' + email.encode(),
                    hashlib.sha256).hexdigest()[:40]


def country_labels(params):
    """Opt-in display metadata never changes stable inventory/user identity."""
    def country(value):
        if not isinstance(value, str) or len(value) > 64 or value != value.strip() or '->' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise PanelError('display countries must be bounded plain labels without arrows or control characters')
        return value
    ingress, exits = {}, {}
    for endpoint in params['ingress_endpoints']:
        primary = country(endpoint.get('display_country', ''))
        for advertised in [endpoint] + (endpoint.get('aliases') or []):
            label = country(primary if advertised.get('display_country') is None else advertised.get('display_country', primary))
            host = advertised['address']
            host = str(ipaddress.ip_address(host)) if is_ip_literal(host) else host.lower()
            ingress[(host, valid_port(advertised['port']))] = label
    if params.get('client_mode') == 'single':
        exits = {name: country(label) for name, label in params.get('exit_countries', {}).items()}
    else:
        for user in params['users']:
            label = country(user.get('exit_display_country', ''))
            if user['exit'] in exits and exits[user['exit']] != label:
                raise PanelError('one exit must have one consistent display country')
            exits[user['exit']] = label
    enabled = any(ingress.values()) or any(exits.values())
    if enabled:
        if not all(ingress.values()) or not all(exits.values()):
            raise PanelError('country labels require every advertised ingress and user exit to be labeled')
        if len(set(ingress.values())) != len(ingress) or len(set(exits.values())) != len(exits):
            raise PanelError('country labels must distinguish every ingress address and exit')
    return enabled, ingress, exits


def validate(params):
    url = urllib.parse.urlsplit(params["url"])
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise PanelError("url must be an HTTP(S) URL without embedded credentials, query or fragment")
    if url.scheme == "http":
        try:
            loopback = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            loopback = url.hostname == "localhost"
        if not loopback:
            raise PanelError("HTTP panel access is permitted only on loopback; use HTTPS remotely")
    valid_port(params["directory_port"])
    valid_port(params["subscription_port"])
    if params.get("subscription_public_url") is not None:
        params["subscription_public_url"] = subscription_origin(params["subscription_public_url"])
    if not params["ingress_endpoints"]:
        raise PanelError("at least one public ingress endpoint is required")
    emails, identifiers = set(), set()
    for user in params["users"]:
        if not user["email"] or not user["sub_id"] or not user["exit"]:
            raise PanelError("users require nonempty email, sub_id and exit")
        if len(user['email']) > 255 or any(ord(char) < 32 or ord(char) == 127 or char.isspace() or char in '/\\' for char in user['email']):
            raise PanelError('email contains characters unsupported by the panel API')
        if any(ord(char) < 32 or ord(char) == 127 or char.isspace() or char in '/\\' for char in user['sub_id']):
            raise PanelError('subscription ID contains characters unsupported by the panel API')
        try:
            user["uuid"] = str(uuid.UUID(user["uuid"]))
        except (ValueError, AttributeError):
            raise PanelError("user UUID is invalid")
        if user["email"] in emails or user["uuid"] in identifiers:
            raise PanelError("user emails and UUIDs must be unique")
        emails.add(user["email"])
        identifiers.add(user["uuid"])
        expiry = user.get('expiry_time', 0)
        if (not isinstance(expiry, int) or isinstance(expiry, bool) or not -(2 ** 63) <= expiry < 2 ** 63 or
                (expiry < 0 and user['enabled'])):
            raise PanelError('expiry_time must be milliseconds; first-use expiry requires a disabled account')
        for field in ['totalGB', 'total_gb', 'limitIp', 'limit_ip', 'limitHwid', 'limit_hwid']:
            if user.get(field, 0) != 0:
                raise PanelError('quota and device limits require central accounting')
        metadata = user.get('metadata', {})
        if not isinstance(metadata, dict):
            raise PanelError('metadata must be an object')
        for key, value in metadata.items():
            valid = (key in {'comment', 'group', 'password', 'auth', 'security', 'source_email', 'source_uuid'} and isinstance(value, str))
            valid |= (key == 'tg_id' and isinstance(value, (str, int)) and not isinstance(value, bool) and
                      re.fullmatch(r'-?[0-9]+', str(value)) is not None and -(2 ** 63) <= int(value) < 2 ** 63)
            valid |= key in {'reset', 'original_expiry_time', 'created_at', 'updated_at'} and isinstance(value, int) and not isinstance(value, bool) and (key != 'reset' or value >= 0)
            if not valid:
                raise PanelError('unsupported metadata field or value type')
    by_email = {user['email']: user for user in params['users']}
    subscriptions = set()
    for user in params['users']:
        owner_name = user.get('subscription_owner') or user['email']
        owner = by_email.get(owner_name)
        if owner is None or (owner.get('subscription_owner') or owner['email']) != owner_name:
            raise PanelError('subscription_owner must name a base user in this configuration')
        if user['enabled'] != owner['enabled']:
            raise PanelError('subscription identities must inherit their owner enabled state')
        if user.get('expiry_time', 0) != owner.get('expiry_time', 0):
            raise PanelError('subscription identities must inherit their owner expiry_time')
        if owner_name != user['email']:
            user['sub_id'] = child_subscription_id(owner['sub_id'], user['email'])
        if user['sub_id'] in subscriptions:
            raise PanelError('panel users require distinct subscription IDs')
        subscriptions.add(user['sub_id'])
    securities = {endpoint["security"] for endpoint in params["ingress_endpoints"]}
    if not securities.issubset({"tls", "reality"}) or len(securities) != 1:
        raise PanelError("all managed endpoints must use one security profile: TLS or REALITY; mixed deployments require separate panels")
    reality_mode = securities == {"reality"}
    if params.get('client_mode', 'grouped') not in ('grouped', 'single'):
        raise PanelError('unknown client_mode')
    if type(params.get('migrate_single_clients', False)) is not bool:
        raise PanelError('migrate_single_clients must be a boolean')
    single = params.get('client_mode', 'grouped') == 'single'
    if params.get('migrate_single_clients') and not single:
        raise PanelError('migrate_single_clients requires single client mode')
    if single:
        selectors = params.get('route_selectors', {})
        countries = params.get('exit_countries', {})
        if not reality_mode:
            raise PanelError('single client mode requires managed REALITY directories')
        if not isinstance(selectors, dict) or not selectors or not isinstance(countries, dict) or set(selectors) != set(countries):
            raise PanelError('single client mode requires a selector and display country for each exit')
        if any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name)
               or type(value) is not int or not 16384 <= value <= 20479 for name, value in selectors.items()):
            raise PanelError('single client selectors must map stable exit names to integers in 16384..20479')
        if len(set(selectors.values())) != len(selectors):
            raise PanelError('single client route selectors must be unique')
        if not all(countries.values()):
            raise PanelError('single client mode requires nonempty exit display countries')
    for user in params["users"]:
        flow = user.get("flow") or ("xtls-rprx-vision" if reality_mode else "")
        if not reality_mode and flow:
            raise PanelError("managed TLS directories require empty flow; use REALITY for managed Vision subscriptions")
        if flow not in ("", "xtls-rprx-vision") or (reality_mode and flow != "xtls-rprx-vision"):
            raise PanelError("REALITY users require xtls-rprx-vision; unsupported user flow")
        user["flow"] = flow
    if not any(endpoint.get('advertise', True) is True for endpoint in params['ingress_endpoints']):
        raise PanelError('at least one ingress endpoint must be advertised')
    if any(not isinstance(endpoint.get('advertise', True), bool) for endpoint in params['ingress_endpoints']):
        raise PanelError('endpoint advertise must be a boolean')
    proxies = []
    endpoint_keys = set()
    profile_names = set()
    for endpoint in params["ingress_endpoints"]:
        address = endpoint["address"]
        aliases = endpoint.get("aliases") or []
        if not isinstance(aliases, list):
            raise PanelError("endpoint aliases must be a list")
        alias_labels = set()
        for alias in aliases:
            if not isinstance(alias, dict) or not {"address", "port", "remark"}.issubset(alias) or set(alias) - {"address", "port", "remark", "display_country"}:
                raise PanelError("aliases require only address, port and remark")
            label = alias["remark"]
            if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", label) or label in alias_labels or label == endpoint.get("remark"):
                raise PanelError("aliases require unique bounded labels in remark")
            alias_labels.add(label)
        for advertised in [endpoint] + aliases:
            host = advertised["address"]
            if not isinstance(host, str) or not (valid_dns_name(host) or is_ip_literal(host)):
                raise PanelError("endpoint address must be a hostname or bare IP address")
            canonical = str(ipaddress.ip_address(host)) if is_ip_literal(host) else host.lower()
            key = (canonical, valid_port(advertised["port"]))
            if key in endpoint_keys:
                raise PanelError("public ingress endpoints and aliases must be unique")
            endpoint_keys.add(key)
        if reality_mode:
            name = endpoint.get("remark", "")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name) or name in profile_names:
                raise PanelError("REALITY endpoints require unique stable inventory names in remark")
            profile_names.add(name)
            public_key = endpoint.get("reality_public_key") or ""
            short_id = endpoint.get("reality_short_id") or ""
            server_name = endpoint.get("reality_server_name") or endpoint.get("tls_server_name") or ""
            target = endpoint.get("reality_target") or ""
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
                raise PanelError("REALITY endpoint requires a URL-base64 X25519 public key")
            if not short_id or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}", short_id):
                raise PanelError("REALITY endpoint requires a nonempty even-length hex short ID of up to 16 characters")
            if not valid_dns_name(server_name) or is_ip_literal(server_name):
                raise PanelError("REALITY endpoint requires an exact nonempty SNI hostname")
            validate_target(target)
            if endpoint.get("reality_fingerprint", "chrome") not in ("chrome", "firefox", "safari"):
                raise PanelError("REALITY fingerprint must be chrome, firefox or safari")
            endpoint["reality_server_name"] = server_name
            proxies.append({"dest": address, "port": endpoint["port"],
                            "remark": name, "forceTls": "same"})
        else:
            proxies.append({"dest": address, "port": endpoint["port"],
                            "remark": endpoint["remark"], "forceTls": "tls",
                            "sni": endpoint.get("tls_server_name") or address})
    labeled, _, _ = country_labels(params)
    known_exits = set(params['route_selectors']) if single else {user['exit'] for user in params['users']}
    for endpoint in params['ingress_endpoints']:
        auto = endpoint.get('auto_selector')
        if auto is not None:
            if not single or type(auto) is not int or not 16384 <= auto <= 20479:
                raise PanelError('auto_selector requires single-client mode and an integer in 16384..20479')
            if auto in params['route_selectors'].values() or 'Auto' in params['exit_countries'].values():
                raise PanelError('Auto must have a distinct selector and display label')
        allowed = endpoint.get('subscription_exits', [])
        if (not isinstance(allowed, list) or any(not isinstance(name, str) or
                not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name) for name in allowed)
                or len(set(allowed)) != len(allowed)):
            raise PanelError('subscription_exits must be a list of distinct stable exit names')
        if allowed and not labeled:
            raise PanelError('subscription_exits filters require complete country labels to suppress native subscription routes')
        if known_exits and set(allowed) - known_exits:
            raise PanelError('subscription_exits references an unknown configured user exit')
    if single:
        if not labeled:
            raise PanelError('single client mode requires country labels')
        return proxies
    for owner in params['users']:
        if (owner.get('subscription_owner') or owner['email']) != owner['email']:
            continue
        owner_exits = {user['exit'] for user in params['users']
                       if (user.get('subscription_owner') or user['email']) == owner['email']}
        if not any(endpoint.get('advertise', True) and
                   (not endpoint.get('subscription_exits', []) or
                    owner_exits.intersection(endpoint['subscription_exits']))
                   for endpoint in params['ingress_endpoints']):
            raise PanelError('subscription exit filters would leave an owner with no published profiles')
    return proxies


def valid_dns_name(value):
    return (isinstance(value, str) and 0 < len(value) <= 253 and
            all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in value.split(".")))


def is_ip_literal(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def subscription_origin(value):
    try:
        if (not isinstance(value, str) or not value or
                any(char.isspace() or ord(char) < 32 for char in value) or
                "?" in value or "#" in value):
            raise ValueError()
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or
                parsed.password is not None or parsed.path not in ("", "/") or
                parsed.query or parsed.fragment or
                not (valid_dns_name(parsed.hostname) or is_ip_literal(parsed.hostname))):
            raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
        return "https://" + parsed.netloc
    except (ValueError, TypeError):
        raise PanelError("subscription_public_url must be an HTTPS origin without credentials, path, query or fragment")


def validate_target(target):
    try:
        parsed = urllib.parse.urlsplit("//" + target)
        if (not parsed.hostname or not parsed.port or parsed.path or parsed.username or
                parsed.password or parsed.query or parsed.fragment or parsed.netloc != target):
            raise ValueError()
        valid_port(parsed.port)
        if not valid_dns_name(parsed.hostname):
            ipaddress.ip_address(parsed.hostname)
    except (ValueError, TypeError):
        raise PanelError("REALITY target must be hostname:port or [IPv6]:port")


def owned_directory(inbound):
    remark = inbound.get("remark", "")
    return remark == DIRECTORY or remark.startswith(DIRECTORY + ":")


def endpoint_proxies(endpoint, primary):
    """Aliases inherit the physical ingress security profile unchanged."""
    return [primary] + [dict(primary, dest=alias["address"], port=alias["port"], remark=alias["remark"])
                        for alias in (endpoint.get("aliases") or [])]


def directory_stream(endpoint, proxy, existing=None):
    """Keep real ingress private keys out of the control database entirely."""
    settings = object_value((existing or {}).get("streamSettings", {})).get("realitySettings", {})
    private_key = settings.get("privateKey")
    if not isinstance(private_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", private_key):
        private_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    return {"network": "tcp", "security": "reality", "externalProxy": endpoint_proxies(endpoint, proxy),
            "realitySettings": {"show": False, "target": endpoint["reality_target"], "xver": 0,
                                "serverNames": [endpoint["reality_server_name"]],
                                "privateKey": private_key, "shortIds": [endpoint["reality_short_id"]],
                                "settings": {"publicKey": endpoint["reality_public_key"],
                                             "fingerprint": endpoint.get("reality_fingerprint", "chrome"),
                                             "spiderX": "/"}}}


def client_payload(record):
    # GET /clients/list has a numeric database id and a separate protocol uuid.
    # POST /clients/update expects the protocol UUID under `id` instead.
    payload = copy.deepcopy(record)
    for field in ("id", "uuid", "inboundIds", "traffic", "createdAt", "updatedAt"):
        payload.pop(field, None)
    payload["id"] = record.get("uuid", "")
    # The database projection stores AllowedIPs as JSON text; the update model
    # expects an array. Empty text is the normal value for VLESS-only clients.
    if isinstance(payload.get("allowedIPs"), str):
        payload["allowedIPs"] = json.loads(payload["allowedIPs"]) if payload["allowedIPs"] else []
    return payload


def differs(existing, desired):
    return any(existing.get(key) != value for key, value in desired.items())


def external_link_payload(row):
    return {key: row.get(key, default) for key, default in
            [('kind', 'link'), ('value', ''), ('remark', ''), ('enable', True),
             ('expiryTime', 0), ('namePrefix', '')]}


def single_proxies(params, endpoint, primary, existing=None):
    """3x-ui v3.11 encodes vlessRoute in bytes 6–7 of the link's UUID."""
    advertised = [endpoint] + (endpoint.get('aliases') or [])
    result = []
    exits = endpoint.get('subscription_exits') or list(params['route_selectors'])
    auto = endpoint.get('auto_selector')
    if auto is not None and params.get('defer_new_auto'):
        previous = object_value((existing or {}).get('streamSettings') or {}).get('externalProxy', [])
        if not any(str(p.get('vlessRoute')) == str(auto) and p.get('remark', '').endswith(' -> Auto')
                   for p in previous):
            auto = None
    for address, proxy in zip(advertised, endpoint_proxies(endpoint, primary)):
        country = address.get('display_country') or endpoint['display_country']
        for exit_name in exits:
            result.append(dict(proxy, vlessRoute=str(params['route_selectors'][exit_name]),
                               remarkFinal=True, remark=country + ' -> ' + params['exit_countries'][exit_name]))
        if auto is not None:
            result.append(dict(proxy, vlessRoute=str(auto), remarkFinal=True, remark=country + ' -> Auto'))
    return result


def is_routed_directory(inbound):
    proxies = object_value(inbound.get('streamSettings') or {}).get('externalProxy') or []
    return any(isinstance(proxy, dict) and 'vlessRoute' in proxy for proxy in proxies)


def migration_plan(params, panel, clients, directories):
    """Read and verify the entire conversion before changing any client or link."""
    manifest = {u['email']: u for u in params['users']}
    records = {r['email']: r for r in clients}
    directory_ids = {r['id'] for r in directories}
    endpoint_exits = {DIRECTORY + ':' + e['remark']: set(e.get('subscription_exits') or params['route_selectors'])
                      for e in params['ingress_endpoints']}
    prior_ids = {d['id'] for d in directories if d['remark'] in endpoint_exits and d.get('enable')}
    new_names = set(endpoint_exits) - {d['remark'] for d in directories}
    family_exits = {}
    for user in manifest.values():
        family_exits.setdefault(user.get('subscription_owner') or user['email'], set()).add(user['exit'])
    expected_children = {u['email']: u for u in manifest.values()
                         if (u.get('subscription_owner') or u['email']) != u['email']}
    for name, child in expected_children.items():
        if name != child['subscription_owner'] + '--' + child['exit']:
            raise PanelError('migration manifest contains a noncanonical child name')
    details = {name: panel.call('/panel/api/clients/get/' + urllib.parse.quote(name, safe=''))
               for name in records}
    addresses = {(str(ipaddress.ip_address(a['address'])) if is_ip_literal(a['address']) else a['address'].lower(), a['port'])
                 for endpoint in params['ingress_endpoints'] for a in [endpoint] + (endpoint.get('aliases') or [])}
    children = []
    cleanup = []
    for rec in clients:
        name = rec['email']
        wanted = manifest.get(name)
        marker = object_value(rec['comment']) if ownership(rec) else {}
        # A generated name alone is not proof of ownership. A marked child
        # absent from the trusted manifest may be a retired/audit identity.
        old_exit = marker.get('exit')
        if wanted is None and isinstance(old_exit, str) and name.endswith('--' + old_exit):
            raise PanelError('unexpected managed exit child is absent from migration manifest')
        child = expected_children.get(name)
        if child is not None:
            owner_name = child['subscription_owner']
            owner = records.get(owner_name)
            if (not owner or not ownership(owner) or owner.get('uuid') != manifest[owner_name]['uuid']
                    or owner.get('subId') != manifest[owner_name]['sub_id'] or not marker
                    or old_exit != child['exit'] or rec.get('uuid') != child['uuid']
                    or rec.get('subId') != child['sub_id']):
                raise PanelError('legacy child or owner credentials/ownership differ from migration manifest')
            attached = set(rec.get('inboundIds') or [])
            owner_ids = set(owner.get('inboundIds') or [])
            owner_links = details[owner_name].get('externalLinks') or []
            has_old_links = any(row.get('kind') == 'link' and (row.get('namePrefix') or '').startswith(LINK_PREFIX)
                                for row in owner_links)
            # DeleteByEmail can partially detach before reporting failure. Once
            # old owned links have been cleared, retry the remaining memberships.
            if attached - directory_ids or attached - owner_ids or (has_old_links and attached != owner_ids):
                raise PanelError('legacy child has differing or unrelated inbound memberships')
            if any(rec.get(k) != owner.get(k) for k in ('enable', 'expiryTime', 'totalGB', 'limitIp', 'limitHwid')):
                raise PanelError('legacy child policy differs from its owner')
        path = urllib.parse.quote(name, safe='')
        rows = details[name].get('externalLinks') or []
        if not isinstance(rows, list):
            raise PanelError('invalid external link list from panel')
        if child is not None:
            if rows:
                raise PanelError('legacy child owns external links; preserve them before conversion')
            children.append(path)
            continue
        kept = []
        for row in rows:
            prefix = row.get('namePrefix') or ''
            if row.get('kind') != 'link' or not prefix.startswith(LINK_PREFIX):
                kept.append(external_link_payload(row))
                continue
            linked = manifest.get(prefix[len(LINK_PREFIX):])
            uri = urllib.parse.urlsplit(row['value'])
            hostname = uri.hostname or ''
            address = str(ipaddress.ip_address(hostname)) if is_ip_literal(hostname) else hostname.lower()
            if (not wanted or marker.get('exit') != wanted['exit'] or rec.get('uuid') != wanted['uuid']
                    or rec.get('subId') != wanted['sub_id'] or not linked
                    or (linked.get('subscription_owner') or linked['email']) != name
                    or uri.scheme != 'vless' or uri.username != linked['uuid']
                    or (address, uri.port) not in addresses):
                raise PanelError('unexpected owned subscription link or owner credentials during migration')
        if wanted and marker:
            if (old_exit != wanted['exit'] or rec.get('uuid') != wanted['uuid']
                    or rec.get('subId') != wanted['sub_id']):
                raise PanelError('legacy owner credentials/ownership differ from migration manifest')
            memberships = set(rec.get('inboundIds') or [])
            eligible = {d['remark'] for d in directories if d['id'] in memberships}
            if prior_ids and prior_ids <= memberships:
                eligible.update(new_names)
            if any(endpoint_exits.get(remark, set()) - family_exits[name] for remark in eligible):
                raise PanelError('migration would grant exits outside the original subscription assignment')
        if len(kept) != len(rows):
            cleanup.append((path, kept))
    return cleanup, children


def prepare_single_clients(params, panel, clients, directories):
    # Xray masks bytes 6 and 7 during VLESS authentication. A full-UUID
    # uniqueness check alone permits two users to authenticate as each other.
    keys = {}
    managed_ids = {d['id'] for d in directories}
    for client in clients:
        if not managed_ids.intersection(client.get('inboundIds') or []):
            continue
        try:
            raw = uuid.UUID(client['uuid']).bytes
        except (ValueError, TypeError, KeyError, AttributeError):
            raise PanelError('a client attached to a managed directory has no valid VLESS UUID')
        identity = raw[:6] + raw[8:]
        if identity in keys:
            raise PanelError('clients attached to managed directories have colliding masked VLESS UUIDs')
        keys[identity] = client['email']
    if not params.get('migrate_single_clients'):
        planned = {DIRECTORY + ':' + endpoint['remark'] for endpoint in params['ingress_endpoints']}
        legacy_ids = {d['id'] for d in directories if not is_routed_directory(d)
                      and (d['remark'] in planned or d.get('enable'))}
        if any(legacy_ids.intersection(r.get('inboundIds') or []) for r in clients):
            raise PanelError('populated grouped directories require explicit single-client migration')
        records = {r['email']: r for r in clients}
        for record in clients:
            if not ownership(record):
                continue
            old_exit = object_value(record['comment']).get('exit')
            name = record['email']
            if not isinstance(old_exit, str) or not name.endswith('--' + old_exit):
                continue
            owner = records.get(name[:-(len(old_exit) + 2)])
            if (owner and owner.get('subId')
                    and record.get('subId') == child_subscription_id(owner['subId'], name)):
                raise PanelError('remaining grouped child requires explicit single-client migration')
        return [], []
    return migration_plan(params, panel, clients, directories)


def inherit_directory_memberships(panel, inbound_id, sources, child_paths):
    # This marker exists only between creating a new directory and committing
    # its initial membership. Later topology runs respect all UI detaches.
    pending = []
    for record in panel.call('/panel/api/clients/list'):
        attached = set(record.get('inboundIds') or [])
        if (sources <= attached and inbound_id not in attached
                and urllib.parse.quote(record['email'], safe='') not in child_paths):
            pending.append(record['email'])
    if pending:
        result = panel.call('/panel/api/clients/bulkAttach', {'emails': pending, 'inboundIds': [inbound_id]})
        if not isinstance(result, dict) or result.get('errors'):
            raise PanelError('panel could not attach eligible clients to the new directory')
        acknowledged = set(result.get('attached') or []) | set(result.get('skipped') or [])
        if acknowledged != set(pending):
            raise PanelError('panel did not account for all initial directory memberships')
    fresh = next((d for d in panel.call('/panel/api/inbounds/list') if d['id'] == inbound_id), None)
    if not fresh or not owned_directory(fresh):
        raise PanelError('new directory disappeared or changed ownership during initial attachment')
    stream = object_value(fresh['streamSettings'])
    if set(stream.pop(ATTACH_FROM, [])) != sources:
        raise PanelError('new directory attachment state changed during reconciliation')
    panel.call('/panel/api/inbounds/update/' + str(inbound_id), dict(fresh, streamSettings=stream))


def check_native_publication(panel, params, directories):
    # Native Host projection can supersede streamSettings.externalProxy. Check
    # what the pinned panel actually renders before retiring the legacy links.
    owners = {u['email'] for u in params['users'] if (u.get('subscription_owner') or u['email']) == u['email']}
    for client in panel.call('/panel/api/clients/list'):
        if client['email'] not in owners:
            continue
        base = uuid.UUID(client['uuid']).bytes
        expected = set()
        for iid in client.get('inboundIds') or []:
            for proxy in directories.get(iid, []):
                route = int(proxy['vlessRoute']).to_bytes(2, 'big')
                credential = str(uuid.UUID(bytes=base[:6] + route + base[8:]))
                expected.add((proxy['dest'].lower(), proxy['port'], credential, proxy['remark']))
        if not expected:
            continue
        path = urllib.parse.quote(client['email'], safe='')
        addresses = {key[:2] for key in expected}
        seen = []
        for raw in panel.call('/panel/api/clients/links/' + path) or []:
            link = urllib.parse.urlsplit(raw)
            if link.scheme == 'vless' and link.hostname and (link.hostname.lower(), link.port) in addresses:
                seen.append((link.hostname.lower(), link.port, link.username, urllib.parse.unquote(link.fragment)))
        if set(seen) != expected or len(seen) != len(expected):
            raise PanelError('panel did not render the expected native VLESS route or country label; legacy clients retained')


def reconcile_subscription_links(module, panel, active_ids):
    """Compose native child share links without fetching remote subscriptions."""
    changed = False
    exact_labels, ingress_countries, exit_countries = country_labels(module.params)
    published = set()
    endpoint_exits = {}
    for endpoint in module.params['ingress_endpoints']:
        if endpoint.get('advertise', True):
            for advertised in [endpoint] + (endpoint.get('aliases') or []):
                host = advertised['address']
                host = str(ipaddress.ip_address(host)) if is_ip_literal(host) else host.lower()
                key = (host, advertised['port'])
                published.add(key)
                endpoint_exits[key] = endpoint.get('subscription_exits', [])
    for owner in module.params['users']:
        if (owner.get('subscription_owner') or owner['email']) != owner['email']:
            continue
        children = [user for user in module.params['users']
                    if user.get('subscription_owner') == owner['email'] and user['email'] != owner['email']]
        if exact_labels:
            children = [owner] + children
        path = urllib.parse.quote(owner['email'], safe='')
        if module.check_mode:
            records = panel.call('/panel/api/clients/list')
            if not any(record['email'] == owner['email'] for record in records):
                changed |= bool(children)
                continue
        detail = panel.call('/panel/api/clients/get/' + path)
        rows = detail.get('externalLinks') or []
        if not isinstance(rows, list):
            raise PanelError('invalid external link list from panel')
        preserved = [external_link_payload(row) for row in rows
                     if not (row.get('kind') == 'link' and str(row.get('namePrefix', '')).startswith(LINK_PREFIX))]
        desired = list(preserved)
        for child in children:
            expected = {key for key in published if not endpoint_exits[key] or child['exit'] in endpoint_exits[key]}
            child_path = urllib.parse.quote(child['email'], safe='')
            if module.check_mode:
                existing = next((record for record in records if record['email'] == child['email']), None)
                if existing is None or set(existing.get('inboundIds', [])) != set(active_ids):
                    changed = True
                    continue
            child_detail = panel.call('/panel/api/clients/get/' + child_path)
            if set(child_detail.get('inboundIds', [])) != set(active_ids):
                raise PanelError('grouped child must attach exclusively to the managed directory inbounds')
            links = panel.call('/panel/api/clients/links/' + child_path)
            if not isinstance(links, list) or not links:
                raise PanelError('panel returned no generated child links')
            seen = set()
            published_seen = set()
            for link in links:
                parsed = urllib.parse.urlsplit(link)
                if parsed.scheme != 'vless' or parsed.username != child['uuid']:
                    raise PanelError('panel returned an unexpected generated child link')
                host = parsed.hostname
                host = str(ipaddress.ip_address(host)) if is_ip_literal(host) else str(host).lower()
                if (host, parsed.port) not in ingress_countries:
                    raise PanelError('panel returned a generated link outside the configured ingress endpoints')
                if (host, parsed.port) not in expected or link in seen:
                    continue
                seen.add(link)
                endpoint_key = (host, parsed.port)
                if endpoint_key in published_seen:
                    raise PanelError('panel returned ambiguous generated links for one published ingress endpoint')
                published_seen.add(endpoint_key)
                if exact_labels:
                    country = ingress_countries.get((host, parsed.port))
                    if country is None:
                        raise PanelError('panel returned a generated link outside the configured ingress endpoints')
                    label = country + ' -> ' + exit_countries[child['exit']]
                else:
                    label = child['exit'] + ' via ' + str(parsed.hostname) + ':' + str(parsed.port)
                named_link = link.split('#', 1)[0] + '#' + urllib.parse.quote(label, safe='')
                desired.append({'kind': 'link', 'value': named_link, 'remark': label,
                                'enable': child['enabled'], 'expiryTime': 0,
                                'namePrefix': LINK_PREFIX + child['email']})
            if published_seen != expected:
                raise PanelError('panel generated links do not cover every published ingress endpoint')
        current = [external_link_payload(row) for row in rows]
        if current != desired:
            changed = True
            if not module.check_mode:
                panel.call('/panel/api/clients/' + path + '/externalLinks', {'externalLinks': desired})
    return changed


def reconcile_grouped_clients(module, panel, clients, active_ids, reality_mode):
    changed = False
    by_email = {r['email']: r for r in clients}
    desired_by_email = {u['email']: u for u in module.params['users']}
    for email, desired in desired_by_email.items():
        record = by_email.get(email)
        metadata = desired.get('metadata') or {}
        owned = {"email": email, "id": desired["uuid"], "subId": desired["sub_id"],
                 "enable": desired["enabled"], "comment": comment_for(desired["exit"], metadata),
                 "flow": desired.get("flow", "xtls-rprx-vision" if reality_mode else ""),
                 "totalGB": 0, "expiryTime": desired.get('expiry_time', 0), "limitIp": 0, "limitHwid": 0}
        for source, target in [('tg_id', 'tgId'), ('group', 'group'), ('password', 'password'),
                               ('auth', 'auth'), ('security', 'security'), ('reset', 'reset')]:
            if source in metadata:
                owned[target] = int(metadata[source]) if source == 'tg_id' else metadata[source]
        path_email = urllib.parse.quote(email, safe="")
        if record is None:
            changed = True
            if not module.check_mode:
                panel.call("/panel/api/clients/add", {"client": owned, "inboundIds": active_ids})
        else:
            # 3x-ui normalizes flow against attached transports. Attach first so
            # a TLS-to-REALITY migration retains Vision on this same reconcile.
            missing = [iid for iid in active_ids if iid is None or iid not in record.get("inboundIds", [])]
            if missing:
                changed = True
                if not module.check_mode:
                    panel.call("/panel/api/clients/" + path_email + "/attach", {"inboundIds": missing})
            normalized = dict(record, id=record.get("uuid"))
            if missing or differs(normalized, owned):
                changed = True
                if not module.check_mode:
                    payload = client_payload(record)
                    payload.update(owned)
                    panel.call("/panel/api/clients/update/" + path_email, payload)
    for record in clients:
        if ownership(record) and record["email"] not in desired_by_email and record.get("enable", False):
            changed = True
            if not module.check_mode:
                payload = client_payload(record)
                payload["enable"] = False
                panel.call("/panel/api/clients/update/" + urllib.parse.quote(record["email"], safe=""), payload)
    changed |= reconcile_subscription_links(module, panel, active_ids)
    return changed


def validate_grouped_ownership(params, clients, managed_inbounds):
    by_email = {entry["email"]: entry for entry in clients}
    desired_by_email = {entry["email"]: entry for entry in params["users"]}
    for email in desired_by_email:
        if email in by_email and not ownership(by_email[email]):
            raise PanelError("desired email already belongs to an unmanaged client")
    desired_ids = {entry["uuid"]: entry["email"] for entry in params["users"]}
    for record in clients:
        existing_id = str(record.get("uuid", "")).lower()
        if existing_id in desired_ids and desired_ids[existing_id] != record.get("email"):
            raise PanelError("desired UUID is already assigned to a different panel client")
    for inbound in managed_inbounds:
        if any(inbound["id"] in entry.get("inboundIds", []) and not ownership(entry) for entry in clients):
            raise PanelError("unmanaged clients are attached to a managed directory; preserve them in a separate inbound")


def reconcile(module, panel, proxies):
    params = module.params
    inbounds = panel.call("/panel/api/inbounds/list")
    clients = panel.call("/panel/api/clients/list")
    if not isinstance(inbounds, list) or not isinstance(clients, list):
        raise PanelError("panel returned an invalid list response")
    managed_inbounds = [entry for entry in inbounds if owned_directory(entry)]
    remarks = [entry.get("remark") for entry in managed_inbounds]
    if len(remarks) != len(set(remarks)):
        raise PanelError("multiple managed directory inbounds exist; resolve ownership manually")
    by_remark = {entry["remark"]: entry for entry in managed_inbounds}
    single = params.get('client_mode') == 'single'
    if any(inbound.get('protocol') != 'vless' for inbound in managed_inbounds):
        raise PanelError('reserved directory inbound is not VLESS')
    changed = False
    cleanup, children = [], []
    if single:
        cleanup, children = prepare_single_clients(params, panel, clients, managed_inbounds)
    else:
        if any(is_routed_directory(d) for d in managed_inbounds):
            raise PanelError('native single-client directories cannot be reconciled as grouped')
        validate_grouped_ownership(params, clients, managed_inbounds)
    reality_mode = params["ingress_endpoints"][0]["security"] == "reality"
    specs = []
    hide_after_links = set()
    used_ports = {entry["port"] for entry in inbounds}
    for index, endpoint in enumerate(params["ingress_endpoints"] if reality_mode else [None]):
        remark = DIRECTORY + ":" + endpoint["remark"] if reality_mode else DIRECTORY
        existing = by_remark.get(remark)
        listen_port = existing["port"] if existing else params["directory_port"]
        if not existing:
            while listen_port in used_ports:
                listen_port += 1
                valid_port(listen_port)
        used_ports.add(listen_port)
        stream = directory_stream(endpoint, proxies[index], existing) if reality_mode else {
            "network": "tcp", "security": "none", "externalProxy": [
                advertised for physical, primary in zip(params["ingress_endpoints"], proxies) if physical.get("advertise", True)
                for advertised in endpoint_proxies(physical, primary)]}
        if single:
            stream['externalProxy'] = single_proxies(params, endpoint, proxies[index], existing)
        desired = {"remark": remark, "listen": "127.0.0.1", "port": listen_port,
                   "protocol": "vless", "streamSettings": stream, "disableFlow": False,
                   "sniffing": {"enabled": False}, "expiryTime": 0, "total": 0,
                   "excludeFromSub": (not single and country_labels(params)[0]) or (endpoint is not None and not endpoint.get("advertise", True))}
        # Keep existing native entries available until their replacements exist.
        # New unpublished directories are hidden immediately.
        if (not single and country_labels(params)[0] and existing is not None
                and not existing.get("excludeFromSub", False)
                and (endpoint is None or endpoint.get("advertise", True))):
            desired["excludeFromSub"] = False
            hide_after_links.add(existing["id"])
        names = [endpoint["remark"]] if reality_mode else [e.get("remark") or (e["address"] + ":" + str(e["port"])) for e in params["ingress_endpoints"]]
        specs.append((desired, existing, names))
    inbound_ids, active_ids = {}, []
    desired_remarks = {desired["remark"] for desired, _, _ in specs}
    prior_ids = {d['id'] for d in managed_inbounds if single and d['remark'] in desired_remarks
                 and d.get('enable') and ATTACH_FROM not in object_value(d['streamSettings'])}
    child_paths = set(children)
    native_dirs = {}
    # Retire only our own directory profiles. Detaching our owned identities
    # avoids stale TLS/plaintext flow gates during a deliberate profile migration.
    for old in managed_inbounds:
        if old["remark"] in desired_remarks:
            continue
        for record in clients:
            if not single and old["id"] in record.get("inboundIds", []):
                changed = True
                if not module.check_mode:
                    panel.call("/panel/api/clients/" + urllib.parse.quote(record["email"], safe="") + "/detach", {"inboundIds": [old["id"]]})
        if old.get("enable") or not old.get("excludeFromSub"):
            changed = True
            if not module.check_mode:
                payload = copy.deepcopy(old)
                payload["excludeFromSub"] = True
                panel.call("/panel/api/inbounds/update/" + str(old["id"]), payload)
                panel.call("/panel/api/inbounds/setEnable/" + str(old["id"]), {"enable": False})
    for desired, existing, names in specs:
        iid = existing["id"] if existing else None
        pending_sources = set()
        if single:
            if existing is None:
                pending_sources = prior_ids
            else:
                pending_sources = set(object_value(existing['streamSettings']).get(ATTACH_FROM, []))
                if pending_sources - prior_ids:
                    raise PanelError('initial attachment references a missing or retired source directory')
            if pending_sources:
                desired['streamSettings'][ATTACH_FROM] = sorted(pending_sources)
        if existing is None:
            changed = True
            if not module.check_mode:
                created = panel.call("/panel/api/inbounds/add", dict(desired, enable=True,
                                     settings={"clients": [], "decryption": "none"}))
                if not isinstance(created, dict) or not isinstance(created.get("id"), int):
                    raise PanelError("panel did not return a created inbound ID")
                iid = created["id"]
        else:
            normalized = dict(existing)
            normalized["streamSettings"] = object_value(existing.get("streamSettings", {}))
            normalized["sniffing"] = object_value(existing.get("sniffing", {}))
            needs_update = any(normalized.get(k) != v for k, v in desired.items()
                               if k not in ("streamSettings", "sniffing"))
            needs_update |= differs(normalized["streamSettings"], desired["streamSettings"])
            needs_update |= normalized["sniffing"].get("enabled") is not False
            settings = object_value(existing.get("settings", {}))
            needs_update |= settings.get("decryption") != "none"
            if needs_update:
                changed = True
                if not module.check_mode:
                    payload = copy.deepcopy(existing)
                    payload.update(desired)
                    payload["settings"] = dict(settings, decryption="none")
                    panel.call("/panel/api/inbounds/update/" + str(iid), payload)
            if not existing.get("enable", False):
                changed = True
                if not module.check_mode:
                    panel.call("/panel/api/inbounds/setEnable/" + str(iid), {"enable": True})
        active_ids.append(iid)
        inbound_ids.update({name: iid for name in names})
        if pending_sources:
            changed = True
            if not module.check_mode:
                inherit_directory_memberships(panel, iid, pending_sources, child_paths)
        if single and not desired['excludeFromSub']:
            native_dirs[iid] = desired['streamSettings']['externalProxy']
    if cleanup or children:
        changed = True
        if not module.check_mode:
            check_native_publication(panel, params, native_dirs)
            for path, kept in cleanup:
                panel.call('/panel/api/clients/' + path + '/externalLinks', {'externalLinks': kept})
            for path in children:
                panel.call('/panel/api/clients/del/' + path + '?keepTraffic=1', {})
    if not single:
        changed |= reconcile_grouped_clients(module, panel, clients, active_ids, reality_mode)
    if hide_after_links:
        changed = True
        if not module.check_mode:
            # Client attachment/update changes inbound settings; never send the
            # pre-reconcile snapshot back over the newly installed identities.
            fresh = panel.call("/panel/api/inbounds/list")
            if not isinstance(fresh, list):
                raise PanelError('invalid refreshed inbound list')
            pending = set(hide_after_links)
            for inbound in fresh:
                if inbound.get('id') in pending:
                    if not owned_directory(inbound):
                        raise PanelError('directory ownership changed during subscription migration')
                    payload = copy.deepcopy(inbound)
                    payload['excludeFromSub'] = True
                    panel.call('/panel/api/inbounds/update/' + str(inbound['id']), payload)
                    pending.remove(inbound['id'])
            if pending:
                raise PanelError('managed directory disappeared during subscription migration')
    settings = panel.call("/panel/api/setting/all", {})
    if not isinstance(settings, dict):
        raise PanelError("panel returned invalid settings")
    listener_settings = {"subEnable": True, "subPort": params["subscription_port"],
                         "subPath": "/sub/", "subListen": "0.0.0.0"}
    desired_settings = dict(listener_settings)
    if params.get("subscription_public_url") is not None:
        desired_settings["subURI"] = params["subscription_public_url"] + "/sub/"
    if differs(settings, desired_settings):
        changed = True
        if not module.check_mode:
            updated = dict(settings)
            updated.update(desired_settings)
            panel.call("/panel/api/setting/update", updated)
            if differs(settings, listener_settings):
                panel.restart()
    return {"changed": changed, "inbound_id": active_ids[0], "inbound_ids": inbound_ids}


def main():
    module = AnsibleModule(argument_spec={
        "client_mode": {"type": "str", "choices": ["grouped", "single"], "default": "grouped"},
        "route_selectors": {"type": "dict", "default": {}},
        "exit_countries": {"type": "dict", "default": {}},
        "migrate_single_clients": {"type": "bool", "default": False},
        "defer_new_auto": {"type": "bool", "default": False},
        "url": {"type": "str", "required": True},
        "username": {"type": "str", "required": True, "no_log": True},
        "password": {"type": "str", "required": True, "no_log": True},
        "users": {"type": "list", "elements": "dict", "required": True, "options": {
            "email": {"type": "str", "required": True},
            "uuid": {"type": "str", "required": True, "no_log": True},
            "sub_id": {"type": "str", "required": True, "no_log": True},
            "subscription_owner": {"type": "str"},
            "exit": {"type": "str", "required": True},
            "exit_display_country": {"type": "str", "default": ""},
            "enabled": {"type": "bool", "default": True},
            "expiry_time": {"type": "int", "default": 0},
            "metadata": {"type": "dict", "default": {}, "no_log": True},
            "flow": {"type": "str", "choices": ["", "xtls-rprx-vision"]}}},
        "ingress_endpoints": {"type": "list", "elements": "dict", "required": True, "options": {
            "address": {"type": "str", "required": True},
            "port": {"type": "int", "required": True},
            "remark": {"type": "str", "default": ""},
            "display_country": {"type": "str", "default": ""},
            "advertise": {"type": "bool", "default": True},
            "auto_selector": {"type": "int"},
            "subscription_exits": {"type": "list", "elements": "str", "default": []},
            "aliases": {"type": "list", "elements": "dict", "default": [], "options": {
                "address": {"type": "str", "required": True},
                "port": {"type": "int", "required": True},
                "remark": {"type": "str", "required": True},
                "display_country": {"type": "str"}}},
            "security": {"type": "str", "default": "tls", "choices": ["tls", "reality"]},
            "tls_server_name": {"type": "str"},
            "reality_server_name": {"type": "str"},
            "reality_target": {"type": "str"},
            "reality_public_key": {"type": "str", "no_log": True},
            "reality_short_id": {"type": "str", "no_log": True},
            "reality_fingerprint": {"type": "str", "default": "chrome", "choices": ["chrome", "firefox", "safari"]}}},
        "directory_port": {"type": "int", "default": 14443},
        "subscription_port": {"type": "int", "default": 2096},
        "subscription_public_url": {"type": "str"},
    }, supports_check_mode=True)
    try:
        proxies = validate(module.params)
        panel = Panel(module.params["url"], module.params["username"], module.params["password"])
        module.exit_json(**reconcile(module, panel, proxies))
    except PanelError as error:
        module.fail_json(msg=str(error))
    except (KeyError, TypeError, ValueError):
        module.fail_json(msg="unexpected panel response shape; verify 3x-ui v3.11 compatibility")


if __name__ == "__main__":
    main()
