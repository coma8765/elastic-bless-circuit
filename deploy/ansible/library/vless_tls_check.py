#!/usr/bin/python
"""Read-only TLS certificate/key preflight for the deployment controller."""
from __future__ import absolute_import, division, print_function

import ipaddress
import os
import ssl
import stat
import time

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: vless_tls_check
short_description: Verify TLS identity, key pairing and validity before deployment
options:
  cert_path:
    description: PEM certificate or chain, with the leaf certificate first.
    type: path
    required: true
  key_path:
    description: Unencrypted matching PEM private key; group/other permissions must be absent.
    type: path
    required: true
  hostname:
    description: Expected DNS name or bare IP address in the leaf certificate SAN.
    type: str
    required: true
notes:
  - This module reads local files only and always returns changed=false.
  - SAN identities are required; the legacy common-name fallback is not used.
  - Wildcards cover exactly one leftmost DNS label.
  - At least 24 hours of certificate validity must remain.
'''

MIN_VALIDITY_SECONDS = 86400


class CertificateError(Exception):
    pass


def dns_name(value):
    """Normalize a DNS identity without treating wildcard syntax as a pattern."""
    value = value.rstrip(".")
    if not value or "\x00" in value:
        raise CertificateError("hostname is invalid")
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise CertificateError("hostname is invalid")
    labels = normalized.split(".")
    if any(not label or len(label) > 63 for label in labels) or len(normalized) > 253:
        raise CertificateError("hostname is invalid")
    return normalized


def dns_matches(pattern, hostname):
    """Permit only an entire leftmost wildcard, never partial/multi-label globs."""
    try:
        normalized = dns_name(pattern)
    except CertificateError:
        return False
    if "*" not in normalized:
        return normalized == hostname
    labels = normalized.split(".")
    host_labels = hostname.split(".")
    return (len(labels) >= 3 and labels[0] == "*" and
            sum(label.count("*") for label in labels) == 1 and
            len(labels) == len(host_labels) and labels[1:] == host_labels[1:])


def identity_matches(decoded, hostname):
    try:
        expected_ip = ipaddress.ip_address(hostname)
    except ValueError:
        expected_ip = None
    if expected_ip is None:
        normalized = dns_name(hostname)
        if "*" in normalized or any(ch in normalized for ch in "/:@?# \t\r\n"):
            raise CertificateError("hostname must be a DNS name or bare IP address")
        return any(kind == "DNS" and dns_matches(value, normalized)
                   for kind, value in decoded.get("subjectAltName", ()))
    for kind, value in decoded.get("subjectAltName", ()):
        if kind != "IP Address":
            continue
        try:
            if ipaddress.ip_address(value) == expected_ip:
                return True
        except ValueError:
            pass
    return False


def verify(module):
    cert_path, key_path, hostname = [module.params[key] for key in ("cert_path", "key_path", "hostname")]
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        raise CertificateError("certificate and key must exist as regular readable files")
    try:
        key_mode = stat.S_IMODE(os.stat(key_path).st_mode)
        if key_mode & 0o077:
            raise CertificateError("private key must not grant group or other permissions (use chmod 600)")
        if not os.access(cert_path, os.R_OK) or not os.access(key_path, os.R_OK):
            raise CertificateError("certificate and key must be readable by the deployment controller")
        decoded = ssl._ssl._test_decode_cert(cert_path)
        now = time.time()
        not_before = ssl.cert_time_to_seconds(decoded["notBefore"])
        not_after = ssl.cert_time_to_seconds(decoded["notAfter"])
        if now < not_before:
            raise CertificateError("certificate validity has not started")
        if not_after - now < MIN_VALIDITY_SECONDS:
            raise CertificateError("certificate expires in less than 24 hours")
        if not identity_matches(decoded, hostname):
            raise CertificateError("certificate SAN does not match the expected hostname")
        # No passphrase input/prompt is permitted. Only an unencrypted key (or an
        # empty passphrase) is supported by this unattended deployment contract.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path, password="")
    except CertificateError:
        raise
    except (OSError, ValueError, KeyError, ssl.SSLError):
        raise CertificateError("certificate/key parsing or key-pair verification failed")
    openssl = module.get_bin_path("openssl", required=True)
    rc, _stdout, _stderr = module.run_command(
        [openssl, "x509", "-checkend", str(MIN_VALIDITY_SECONDS), "-noout", "-in", cert_path])
    if rc:
        raise CertificateError("OpenSSL certificate validity check failed")
    return {"changed": False, "valid": True, "hostname": hostname,
            "not_after": decoded["notAfter"]}


def main():
    module = AnsibleModule(argument_spec={
        "cert_path": {"type": "path", "required": True},
        "key_path": {"type": "path", "required": True},
        "hostname": {"type": "str", "required": True},
    }, supports_check_mode=True)
    try:
        module.exit_json(**verify(module))
    except CertificateError as error:
        module.fail_json(msg=str(error), changed=False)


if __name__ == "__main__":
    main()
