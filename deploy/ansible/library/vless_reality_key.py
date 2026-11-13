#!/usr/bin/python
"""Persist one X25519 REALITY identity without putting private keys in inventory."""
import base64
import json
import os
import re
import secrets
import stat
import tempfile

from ansible.module_utils.basic import AnsibleModule
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


def identity(path):
    if os.path.lexists(path):
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('REALITY identity must be a regular private file (0600)')
        with open(path) as source:
            record = json.load(source)
        if not isinstance(record, dict):
            raise ValueError('invalid stored REALITY identity')
        for field in ('private_key', 'public_key'):
            if not isinstance(record.get(field), str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', record[field]):
                raise ValueError('invalid stored REALITY identity')
        if not isinstance(record.get('short_id'), str) or not re.fullmatch(r'[0-9a-f]{16}', record['short_id']):
            raise ValueError('invalid stored REALITY short ID')
        derived = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(record['private_key'] + '='))
        public = base64.urlsafe_b64encode(derived.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode().rstrip('=')
        if public != record['public_key']:
            raise ValueError('stored REALITY key pair does not match')
        return record, False
    key = X25519PrivateKey.generate()
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip('=')
    record = dict(private_key=encode(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())),
                  public_key=encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)), short_id=secrets.token_hex(8))
    fd, temporary = tempfile.mkstemp(prefix='.reality-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w') as destination:
            json.dump(record, destination)
            destination.write('\n')
            destination.flush()
            os.fsync(destination.fileno())
        # Exclusive publication prevents two controllers from silently rotating an identity.
        os.link(temporary, path)
    finally:
        os.unlink(temporary)
    directory_fd = os.open(os.path.dirname(path) or '.', os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return record, True


def main():
    module = AnsibleModule(argument_spec={'path': {'type': 'path', 'required': True}})
    try:
        record, changed = identity(module.params['path'])
        module.exit_json(changed=changed, public_key=record['public_key'], short_id=record['short_id'])
    except (OSError, ValueError, KeyError):
        module.fail_json(msg='could not create or validate private REALITY identity; check file permissions and controller cryptography support')


if __name__ == '__main__':
    main()
