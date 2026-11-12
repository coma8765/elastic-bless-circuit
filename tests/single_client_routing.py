#!/usr/bin/env python3
"""Exercise the compiled ingress renderer and (when supplied) real Xray listeners.

Run with --agent /path/to/node-agent and optionally --xray /path/to/xray.
The wire test uses only loopback sockets, synthetic identities and temporary files.
"""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

AGENT = Path(os.environ.get("NODE_AGENT_BINARY", "build/ci/node-agent"))
XRAY = os.environ.get("XRAY_BINARY")
OWNER = "b1d480af-0403-48ad-ae6c-a430d02cef11"
ALIAS = "38579aac-36ab-438e-bda3-f79d6c9b8007"
NEW = "2911aca9-6f4e-4d63-84b1-d83d8b18e979"
EAST, WEST = 0x4001, 0x4002


def variant(identifier, selector):
    raw = bytearray(uuid.UUID(identifier).bytes)
    raw[6:8] = selector.to_bytes(2, "big")
    return str(uuid.UUID(bytes=bytes(raw)))


def raw_selector(identifier):
    return int(identifier.split("-")[2], 16)


def row(identifier, **changes):
    return {"id": identifier, "email": "display-name", **changes}


class SingleClient(unittest.TestCase):
    def reserve_port(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        self.reservations[port] = sock
        self.addCleanup(sock.close)
        return port

    def setUp(self):
        self.reservations = {}
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = {
            "role": "in",
            "allow_insecure_lab": True,
            "listener": {"address": "127.0.0.1", "port": self.reserve_port()},
            "exits": [],
            "single_client": {
                "selectors": {"east": EAST, "west": WEST},
                "legacy": [{"owner": OWNER, "primary": "east", "aliases": [{"id": ALIAS, "exit": "west"}]}],
            },
        }
        for name in ("east", "west"):
            secret = self.directory / (name + ".uuid")
            secret.write_text(str(uuid.uuid4()))
            self.config["exits"].append(
                {"name": name, "address": "127.0.0.1", "port": self.reserve_port(), "uuid_file": str(secret)}
            )

    def render(self, users, valid=True):
        config = self.directory / "node.json"
        config.write_text(json.dumps(self.config))
        snapshot = self.directory / "users.json"
        snapshot.write_text(json.dumps(users))
        result = subprocess.run(
            [str(AGENT), "render", str(config), str(snapshot)], capture_output=True, text=True, timeout=10
        )
        if not valid:
            self.assertNotEqual(result.returncode, 0)
            return None
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def routes(self, users):
        config = self.render(users)
        clients = config["inbounds"][0]["settings"]["clients"]
        by_label = {c["email"]: c["id"] for c in clients}
        self.assertEqual(len(by_label), len(clients))
        self.assertEqual(config["outbounds"][0]["protocol"], "blackhole")
        self.assertFalse(any(out["protocol"] == "freedom" for out in config["outbounds"]))
        return {(by_label[u], r["vlessRoute"], r["outboundTag"])
                for r in config["routing"]["rules"] for u in r["user"]}

    def test_one_native_owner_per_identity_and_stable_legacy_routes(self):
        expected = {
            (OWNER, EAST, "east"), (OWNER, WEST, "west"),
            (OWNER, raw_selector(OWNER), "east"), (ALIAS, raw_selector(ALIAS), "west"),
            (NEW, EAST, "east"), (NEW, WEST, "west"),
        }
        # A legacy panel/cached child is never processed as an independent user.
        self.assertEqual(self.routes([row(NEW), row(ALIAS), row(OWNER)]), expected)
        self.assertEqual(self.routes([row(OWNER, email="regexp:.*"), row(NEW)]), expected)
        rendered = self.render([row(NEW, email="regexp:.*")])
        self.assertEqual(len(rendered["inbounds"][0]["settings"]["clients"]), 1)
        self.assertNotIn("regexp:.*", json.dumps(rendered))

    def test_owner_removal_rotation_and_supported_policy(self):
        good = {(NEW, EAST, "east"), (NEW, WEST, "west")}
        for change in [
            {"enable": False}, {"expiryTime": 1}, {"expiryTime": -1}, {"totalGB": 1},
            {"limitHwid": 1}, {"limitIp": 1}, {"flow": "unsupported"},
            {"expiryTime": "invalid"}, {"expiryTime": 2**63}, {"enable": "invalid"},
        ]:
            with self.subTest(change=change):
                self.assertEqual(self.routes([row(NEW), row(ALIAS), row(OWNER, **change)]), good)
        self.assertEqual(self.routes([row(NEW), row(ALIAS)]), good)
        # A newly rotated owner UUID has its eligible selectors but no previous aliases.
        self.assertEqual(self.routes([row(NEW, email="renamed"), row(ALIAS)]), good)
        self.assertEqual(self.routes([]), set())

    def test_normalized_collision_denies_both_and_preserves_unrelated_owners(self):
        self.assertEqual(self.routes([row(OWNER), row(variant(OWNER, 0x4044)), row(NEW)]),
                         {(NEW, EAST, "east"), (NEW, WEST, "west")})
        self.assertEqual(self.routes([row(NEW), row(variant(NEW, EAST), enable=False)]), set())
        self.config["single_client"]["legacy"][0]["aliases"][0]["id"] = variant(OWNER, EAST)
        self.render([], valid=False)

    def test_per_ingress_selector_scope_and_migration_conflicts(self):
        self.config["single_client"]["selectors"] = {"west": WEST}
        self.assertEqual(self.routes([row(NEW)]), {(NEW, WEST, "west")})
        self.assertEqual(self.routes([row(OWNER)]), {
            (OWNER, WEST, "west"), (ALIAS, raw_selector(ALIAS), "west")
        })
        self.config["single_client"]["legacy"][0]["owner"] = variant(OWNER, WEST)
        self.render([], valid=False)
        self.config["single_client"]["legacy"] = []
        for selectors in [{}, {"east": EAST, "west": EAST}, {"unknown": EAST}, {"east": 0x5000}]:
            self.config["single_client"]["selectors"] = selectors
            self.render([], valid=False)

    def test_native_xray_routes_and_denials(self):
        if not XRAY:
            self.skipTest("set --xray to run the real local protocol test")

        def start_xray(name, config, port, stack):
            path = self.directory / (name + ".json")
            path.write_text(json.dumps(config))
            checked = subprocess.run([XRAY, "run", "-test", "-config", str(path)], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            for listener in config["inbounds"]:
                self.reservations.pop(listener["port"]).close()
            log = stack.enter_context((self.directory / (name + ".log")).open("w"))
            process = subprocess.Popen([XRAY, "run", "-config", str(path)], stdout=log, stderr=subprocess.STDOUT)
            def stop():
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            stack.callback(stop)
            for _ in range(100):
                self.assertIsNone(process.poll(), name + " exited")
                with socket.socket() as sock:
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        return
                time.sleep(0.02)
            self.fail(name + " did not start")

        def handler_for(exit_name):
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(exit_name.encode())))
                    self.end_headers()
                    self.wfile.write(exit_name.encode())
                def log_message(self, *args):
                    pass
            return Handler

        with contextlib.ExitStack() as stack:
            exits = {"inbounds": [], "outbounds": [], "routing": {"rules": []}}
            for entry in self.config["exits"]:
                name = entry["name"]
                server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_for(name))
                stack.callback(server.server_close)
                stack.callback(server.shutdown)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                exits["inbounds"].append({
                    "tag": name, "listen": "127.0.0.1", "port": entry["port"], "protocol": "vless",
                    "settings": {"decryption": "none", "clients": [{"id": Path(entry["uuid_file"]).read_text()}]},
                })
                exits["outbounds"].append({
                    "tag": name, "protocol": "freedom",
                    "settings": {"redirect": "127.0.0.1:" + str(server.server_port),
                                 "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]},
                })
                exits["routing"]["rules"].append({"type": "field", "inboundTag": [name], "outboundTag": name})
            start_xray("exits", exits, exits["inbounds"][0]["port"], stack)
            ingress = self.render([row(OWNER), row(ALIAS), row(NEW)])
            ingress_port = self.config["listener"]["port"]
            start_xray("ingress", ingress, ingress_port, stack)
            cases = [(variant(OWNER, EAST), "east"), (variant(OWNER, WEST), "west"),
                     (OWNER, "east"), (ALIAS, "west"), (variant(NEW, WEST), "west"),
                     (variant(OWNER, WEST + 1), None), (variant(ALIAS, EAST), None),
                     (variant(str(uuid.uuid4()), WEST), None)]
            client = {"inbounds": [], "outbounds": [], "routing": {"rules": []}}
            for i, (wire_id, _) in enumerate(cases):
                name = "probe-" + str(i)
                client["inbounds"].append({"tag": name, "listen": "127.0.0.1", "port": self.reserve_port(), "protocol": "socks"})
                client["outbounds"].append({"tag": name, "protocol": "vless", "settings": {
                    "vnext": [{"address": "127.0.0.1", "port": ingress_port,
                               "users": [{"id": wire_id, "encryption": "none"}]}]}})
                client["routing"]["rules"].append({"type": "field", "inboundTag": [name], "outboundTag": name})
            start_xray("client", client, client["inbounds"][0]["port"], stack)
            for inbound, (_, expected) in zip(client["inbounds"], cases):
                with self.subTest(case=inbound["tag"], expected=expected):
                    probe = subprocess.run(
                        ["curl", "--noproxy", "", "-fsS", "--socks5-hostname",
                         "127.0.0.1:" + str(inbound["port"]), "--max-time", "3", "http://127.0.0.1:80/"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if expected:
                        self.assertEqual((probe.returncode, probe.stdout), (0, expected), probe.stderr)
                    else:
                        self.assertNotEqual(probe.returncode, 0)
                        self.assertEqual(probe.stdout, "")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--agent", type=Path, default=AGENT)
    parser.add_argument("--xray", default=XRAY)
    args, unittest_args = parser.parse_known_args()
    AGENT, XRAY = args.agent.resolve(), args.xray
    unittest.main(argv=[sys.argv[0], *unittest_args])
