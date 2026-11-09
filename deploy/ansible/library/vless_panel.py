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
  users:
    description: Owned client identities; omitted previously owned identities are disabled.
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
  - The inbound remark vless-mesh-ansible-directory-v1 is reserved for this module.
  - Client comments contain an ownership marker; removing it relinquishes ownership.
  - Removed managed clients are disabled globally but remain in the panel for audit.
  - Check mode authenticates and reads state, but makes no configuration changes.
'''

MANAGED = "vless-mesh-ansible/v1"
DIRECTORY = "vless-mesh-ansible-directory-v1"


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


def comment_for(exit_name):
    return json.dumps({"managed_by": MANAGED, "exit": exit_name}, sort_keys=True, separators=(",", ":"))


def valid_port(value):
    if value < 1 or value > 65535:
        raise PanelError("ports must be in 1..65535")
    return value


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
        try:
            user["uuid"] = str(uuid.UUID(user["uuid"]))
        except (ValueError, AttributeError):
            raise PanelError("user UUID is invalid")
        if user["email"] in emails or user["uuid"] in identifiers:
            raise PanelError("user emails and UUIDs must be unique")
        emails.add(user["email"])
        identifiers.add(user["uuid"])
    securities = {endpoint["security"] for endpoint in params["ingress_endpoints"]}
    if not securities.issubset({"tls", "reality"}) or len(securities) != 1:
        raise PanelError("all managed endpoints must use one security profile: TLS or REALITY; mixed deployments require separate panels")
    reality_mode = securities == {"reality"}
    for user in params["users"]:
        flow = user.get("flow") or ("xtls-rprx-vision" if reality_mode else "")
        if not reality_mode and flow:
            raise PanelError("managed TLS directories require empty flow; use REALITY for managed Vision subscriptions")
        if flow not in ("", "xtls-rprx-vision") or (reality_mode and flow != "xtls-rprx-vision"):
            raise PanelError("REALITY users require xtls-rprx-vision; unsupported user flow")
        user["flow"] = flow
    proxies = []
    endpoint_keys = set()
    profile_names = set()
    for endpoint in params["ingress_endpoints"]:
        address = endpoint["address"]
        if not address or any(ch in address for ch in "/?#@\r\n\t "):
            raise PanelError("endpoint address must be a hostname or bare IP address")
        key = (address, valid_port(endpoint["port"]))
        if key in endpoint_keys:
            raise PanelError("public ingress endpoints must be unique")
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


def directory_stream(endpoint, proxy, existing=None):
    """Keep real ingress private keys out of the control database entirely."""
    settings = object_value((existing or {}).get("streamSettings", {})).get("realitySettings", {})
    private_key = settings.get("privateKey")
    if not isinstance(private_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", private_key):
        private_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    return {"network": "tcp", "security": "reality", "externalProxy": [proxy],
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
        if inbound.get("protocol") != "vless":
            raise PanelError("reserved directory inbound is not VLESS")
        if any(inbound["id"] in entry.get("inboundIds", []) and not ownership(entry) for entry in clients):
            raise PanelError("unmanaged clients are attached to a managed directory; preserve them in a separate inbound")
    reality_mode = params["ingress_endpoints"][0]["security"] == "reality"
    specs = []
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
            "network": "tcp", "security": "none", "externalProxy": proxies}
        desired = {"remark": remark, "listen": "127.0.0.1", "port": listen_port,
                   "protocol": "vless", "streamSettings": stream, "disableFlow": False,
                   "sniffing": {"enabled": False}, "expiryTime": 0, "total": 0,
                   "excludeFromSub": False}
        names = [endpoint["remark"]] if reality_mode else [e.get("remark") or (e["address"] + ":" + str(e["port"])) for e in params["ingress_endpoints"]]
        specs.append((desired, existing, names))
    changed, inbound_ids, active_ids = False, {}, []
    desired_remarks = {desired["remark"] for desired, _, _ in specs}
    # Retire only our own directory profiles. Detaching our owned identities
    # avoids stale TLS/plaintext flow gates during a deliberate profile migration.
    for old in managed_inbounds:
        if old["remark"] in desired_remarks:
            continue
        for record in clients:
            if old["id"] in record.get("inboundIds", []):
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
    for email, desired in desired_by_email.items():
        record = by_email.get(email)
        owned = {"email": email, "id": desired["uuid"], "subId": desired["sub_id"],
                 "enable": desired["enabled"], "comment": comment_for(desired["exit"]),
                 "flow": desired.get("flow", "xtls-rprx-vision" if reality_mode else ""),
                 "totalGB": 0, "expiryTime": 0, "limitIp": 0, "limitHwid": 0}
        path_email = urllib.parse.quote(email, safe="")
        if record is None:
            changed = True
            if not module.check_mode:
                panel.call("/panel/api/clients/add", {"client": owned, "inboundIds": active_ids})
        else:
            normalized = dict(record, id=record.get("uuid"))
            if differs(normalized, owned):
                changed = True
                if not module.check_mode:
                    payload = client_payload(record)
                    payload.update(owned)
                    panel.call("/panel/api/clients/update/" + path_email, payload)
            missing = [iid for iid in active_ids if iid is None or iid not in record.get("inboundIds", [])]
            if missing:
                changed = True
                if not module.check_mode:
                    panel.call("/panel/api/clients/" + path_email + "/attach", {"inboundIds": missing})
    for record in clients:
        if ownership(record) and record["email"] not in desired_by_email and record.get("enable", False):
            changed = True
            if not module.check_mode:
                payload = client_payload(record)
                payload["enable"] = False
                panel.call("/panel/api/clients/update/" + urllib.parse.quote(record["email"], safe=""), payload)
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
        "url": {"type": "str", "required": True},
        "username": {"type": "str", "required": True, "no_log": True},
        "password": {"type": "str", "required": True, "no_log": True},
        "users": {"type": "list", "elements": "dict", "required": True, "options": {
            "email": {"type": "str", "required": True},
            "uuid": {"type": "str", "required": True, "no_log": True},
            "sub_id": {"type": "str", "required": True, "no_log": True},
            "exit": {"type": "str", "required": True},
            "enabled": {"type": "bool", "default": True},
            "flow": {"type": "str", "choices": ["", "xtls-rprx-vision"]}}},
        "ingress_endpoints": {"type": "list", "elements": "dict", "required": True, "options": {
            "address": {"type": "str", "required": True},
            "port": {"type": "int", "required": True},
            "remark": {"type": "str", "default": ""},
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
