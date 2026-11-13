#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0
"""Bind previously issued route credentials to their canonical panel owner."""
import json
import os
import stat
import tempfile
import uuid

from ansible.module_utils.basic import AnsibleModule


def compatibility_owners(users, selectors):
    owners = {}
    normalized_ids = set()
    for user in users:
        identifier = uuid.UUID(user['uuid'])
        key = identifier.bytes[:6] + identifier.bytes[8:]
        if key in normalized_ids:
            raise ValueError('two inventory UUIDs have the same VLESS authentication key')
        normalized_ids.add(key)
        name = user.get('subscription_owner') or user['email']
        group = owners.setdefault(name, {'aliases': [], 'exits': set()})
        exit_name = user['exit']
        if exit_name not in selectors or exit_name in group['exits']:
            raise ValueError('invalid or repeated exit in an existing client group')
        group['exits'].add(exit_name)
        if user['email'] == name:
            group.update(owner=str(identifier), primary=exit_name)
            raw_selector = int.from_bytes(identifier.bytes[6:8], 'big')
            if any(value == raw_selector and other != exit_name for other, value in selectors.items()):
                raise ValueError('a selector would change the exit of an existing base UUID; choose another selector')
        else:
            group['aliases'].append({'id': str(identifier), 'exit': exit_name})
    for group in owners.values():
        if 'owner' not in group or group.pop('exits') != set(selectors):
            raise ValueError('single-client migration requires an owner with the same complete exit set for each existing group')
    return list(owners.values())


def resolve_manifest(path, users, selectors, migrate, check_mode):
    """Keep exactly the credentials that existed at cutover across later topology changes."""
    candidate = compatibility_owners(users, selectors) if migrate else []
    if os.path.lexists(path):
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('legacy manifest must be a private regular file')
        with open(path) as stream:
            saved = json.load(stream)
        if not isinstance(saved, list) or (migrate and saved != candidate):
            raise ValueError('stored compatibility manifest differs from the migration input')
        return saved, False
    if not migrate or check_mode:
        return candidate, False
    fd, temporary = tempfile.mkstemp(prefix='.legacy-', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(candidate, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            return resolve_manifest(path, users, selectors, migrate, check_mode)
    finally:
        os.unlink(temporary)
    return candidate, True


def main():
    module = AnsibleModule(argument_spec={
        'users': {'type': 'list', 'elements': 'dict', 'required': True, 'no_log': True},
        'selectors': {'type': 'dict', 'required': True},
        'path': {'type': 'path', 'required': True},
        'migrate': {'type': 'bool', 'default': False},
    }, supports_check_mode=True)
    try:
        _, changed = resolve_manifest(module.params['path'], module.params['users'],
                                           module.params['selectors'], module.params['migrate'], module.check_mode)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        module.fail_json(msg='Cannot verify single-client compatibility manifest: ' + str(exc))
    module.exit_json(changed=changed, present=os.path.isfile(module.params['path']))


if __name__ == '__main__':
    main()
