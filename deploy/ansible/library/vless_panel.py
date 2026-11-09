#!/usr/bin/python
"""Idempotent 3x-ui v3.11 directory/subscription configuration.

Ownership is explicit: one reserved inbound remark and a JSON client comment.
The module never adopts, deletes or detaches an unrelated panel object.
"""
from __future__ import absolute_import, division, print_function

import copy
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
    description: Public TLS ingress endpoints advertised in client subscriptions.
    type: list
    elements: dict
    required: true
  directory_port:
    type: int
    default: 14443
  subscription_port:
    type: int
    default: 2096
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
    if not params["ingress_endpoints"]:
        raise PanelError("at least one public TLS ingress endpoint is required")
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
    proxies = []
    endpoint_keys = set()
    for endpoint in params["ingress_endpoints"]:
        address = endpoint["address"]
        if not address or any(ch in address for ch in "/?#@\r\n\t "):
            raise PanelError("endpoint address must be a hostname or bare IP address")
        if endpoint["security"] != "tls":
            raise PanelError("managed subscription endpoints require TLS")
        key = (address, valid_port(endpoint["port"]))
        if key in endpoint_keys:
            raise PanelError("public ingress endpoints must be unique")
        endpoint_keys.add(key)
        proxies.append({"dest": address, "port": endpoint["port"],
                        "remark": endpoint["remark"], "forceTls": "tls",
                        "sni": endpoint.get("tls_server_name") or address})
    return proxies


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
    matching = [entry for entry in inbounds if entry.get("remark") == DIRECTORY]
    if len(matching) > 1:
        raise PanelError("multiple managed directory inbounds exist; resolve ownership manually")
    inbound = matching[0] if matching else None
    iid = inbound["id"] if inbound else None
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
    if inbound:
        if inbound.get("protocol") != "vless":
            raise PanelError("reserved directory inbound is not VLESS")
        if any(iid in entry.get("inboundIds", []) and not ownership(entry) for entry in clients):
            raise PanelError("unmanaged clients are attached to the dedicated directory; preserve them in a separate inbound")
    desired_stream = {"network": "tcp", "security": "none", "externalProxy": proxies}
    desired_inbound = {"remark": DIRECTORY, "listen": "127.0.0.1", "port": params["directory_port"],
                       "protocol": "vless", "streamSettings": desired_stream,
                       "sniffing": {"enabled": False}, "expiryTime": 0, "total": 0,
                       "excludeFromSub": False}
    changed = False
    if not inbound:
        changed = True
        if not module.check_mode:
            created = panel.call("/panel/api/inbounds/add", dict(desired_inbound, enable=True,
                                 settings={"clients": [], "decryption": "none"}))
            if not isinstance(created, dict) or not isinstance(created.get("id"), int):
                raise PanelError("panel did not return a created inbound ID")
            iid = created["id"]
    else:
        normalized = dict(inbound)
        normalized["streamSettings"] = object_value(inbound.get("streamSettings", {}))
        normalized["sniffing"] = object_value(inbound.get("sniffing", {}))
        # Upstream may enrich transport/sniffing defaults; compare only owned fields.
        needs_update = any(normalized.get(k) != v for k, v in desired_inbound.items()
                           if k not in ("streamSettings", "sniffing"))
        needs_update |= differs(normalized["streamSettings"], desired_stream)
        needs_update |= normalized["sniffing"].get("enabled") is not False
        settings = object_value(inbound.get("settings", {}))
        needs_update |= settings.get("decryption") != "none"
        if needs_update:
            changed = True
            if not module.check_mode:
                payload = copy.deepcopy(inbound)
                payload.update(desired_inbound)
                payload["settings"] = dict(settings, decryption="none")
                panel.call("/panel/api/inbounds/update/" + str(iid), payload)
        if not inbound.get("enable", False):
            changed = True
            if not module.check_mode:
                panel.call("/panel/api/inbounds/setEnable/" + str(iid), {"enable": True})
    for email, desired in desired_by_email.items():
        record = by_email.get(email)
        owned = {"email": email, "id": desired["uuid"], "subId": desired["sub_id"],
                 "enable": desired["enabled"], "comment": comment_for(desired["exit"]),
                 "flow": "", "totalGB": 0, "expiryTime": 0, "limitIp": 0, "limitHwid": 0}
        path_email = urllib.parse.quote(email, safe="")
        if record is None:
            changed = True
            if not module.check_mode:
                panel.call("/panel/api/clients/add", {"client": owned, "inboundIds": [iid]})
        else:
            normalized = dict(record, id=record.get("uuid"))
            if differs(normalized, owned):
                changed = True
                if not module.check_mode:
                    payload = client_payload(record)
                    payload.update(owned)
                    panel.call("/panel/api/clients/update/" + path_email, payload)
            if iid is None or iid not in record.get("inboundIds", []):
                changed = True
                if not module.check_mode:
                    panel.call("/panel/api/clients/" + path_email + "/attach", {"inboundIds": [iid]})
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
    desired_settings = {"subEnable": True, "subPort": params["subscription_port"],
                        "subPath": "/sub/", "subListen": "0.0.0.0"}
    if differs(settings, desired_settings):
        changed = True
        if not module.check_mode:
            updated = dict(settings)
            updated.update(desired_settings)
            panel.call("/panel/api/setting/update", updated)
            panel.restart()
    return {"changed": changed, "inbound_id": iid}


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
            "enabled": {"type": "bool", "default": True}}},
        "ingress_endpoints": {"type": "list", "elements": "dict", "required": True, "options": {
            "address": {"type": "str", "required": True},
            "port": {"type": "int", "required": True},
            "remark": {"type": "str", "default": ""},
            "security": {"type": "str", "default": "tls", "choices": ["tls"]},
            "tls_server_name": {"type": "str"}}},
        "directory_port": {"type": "int", "default": 14443},
        "subscription_port": {"type": "int", "default": 2096},
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
