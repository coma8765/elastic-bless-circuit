#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0
"""Validate and expand subscription account routes before writing identities."""
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: vless_user_routes
short_description: Validate and expand managed subscription exit identities
options:
  users:
    type: list
    elements: dict
    required: true
  exits:
    type: list
    elements: str
    required: true
notes:
  - Performs no filesystem, network or panel operations.
  - Additional exit identities are composed into their base account's public subscription.
'''


class ExpansionError(Exception):
    pass


def valid_name(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value) is not None


def validate_profile(user):
    enabled = user.get('enabled', True)
    expiry = user.get('expiry_time', 0)
    if not isinstance(enabled, bool):
        raise ExpansionError('user enabled must be a boolean')
    if not isinstance(expiry, int) or isinstance(expiry, bool) or expiry < -(2 ** 63) or expiry >= 2 ** 63:
        raise ExpansionError('expiry_time must be a signed millisecond integer')
    if expiry < 0 and enabled:
        raise ExpansionError('first-use expiry requires a disabled account until normalized')
    for key in ['totalGB', 'total_gb', 'limitIp', 'limit_ip', 'limitHwid', 'limit_hwid']:
        if key in user and user[key] != 0:
            raise ExpansionError('quota and device limits require central accounting')
    metadata = user.get('metadata', {})
    if not isinstance(metadata, dict):
        raise ExpansionError('metadata must be an object')
    strings = {'comment', 'group', 'password', 'auth', 'security', 'source_email', 'source_uuid'}
    integers = {'reset', 'original_expiry_time', 'created_at', 'updated_at'}
    for key, value in metadata.items():
        if key in strings and isinstance(value, str):
            continue
        if (key == 'tg_id' and isinstance(value, (str, int)) and not isinstance(value, bool) and
                re.fullmatch(r'-?[0-9]+', str(value)) and -(2 ** 63) <= int(value) < 2 ** 63):
            continue
        if key in integers and isinstance(value, int) and not isinstance(value, bool) and (key != 'reset' or value >= 0):
            continue
        raise ExpansionError('unsupported metadata field or value type')
    return enabled, expiry, metadata


def expand(users, exits):
    if not isinstance(exits, list) or not exits or any(not valid_name(name) for name in exits):
        raise ExpansionError('exits must be a nonempty list of valid inventory names')
    if len(set(exits)) != len(exits):
        raise ExpansionError('exit inventory names must be unique')
    if not isinstance(users, list):
        raise ExpansionError('users must be a list')
    result, emails, state_keys = [], set(), set()
    for user in users:
        if (not isinstance(user, dict) or not isinstance(user.get('email'), str) or
                not 0 < len(user['email']) <= 255 or any(ord(char) < 32 or ord(char) == 127 or char.isspace() or char in '/\\' for char in user['email'])):
            raise ExpansionError('users require email labels without whitespace, slashes or control characters')
        state_key = user.get('identity_key', user['email'])
        if not valid_name(state_key):
            raise ExpansionError('unsafe email filenames require an explicit safe identity_key of at most 64 characters')
        primary, additional = user.get('exit'), user.get('additional_exits', [])
        if not valid_name(primary) or primary not in exits:
            raise ExpansionError('each user exit must name a configured exit')
        if not isinstance(additional, list) or any(not valid_name(name) for name in additional):
            raise ExpansionError('additional_exits must be a list of valid exit inventory names')
        if len(set(additional)) != len(additional) or primary in additional:
            raise ExpansionError('additional_exits must be unique and exclude the primary exit')
        if any(name not in exits for name in additional):
            raise ExpansionError('additional_exits must name configured exits')
        enabled, expiry, metadata = validate_profile(user)
        for index, exit_name in enumerate([primary] + additional):
            email = user['email'] if index == 0 else user['email'] + '--' + exit_name
            identity_key = state_key if index == 0 else state_key + '--' + exit_name
            if len(email) > 255 or not valid_name(identity_key):
                raise ExpansionError('derived state labels must be at most 64 characters and emails at most 255')
            if email in emails:
                raise ExpansionError('base and derived user emails must be globally unique')
            emails.add(email)
            if identity_key in state_keys:
                raise ExpansionError('base and derived identity_key values must be globally unique')
            state_keys.add(identity_key)
            record = {'email': email, 'base_email': user['email'], 'exit': exit_name, 'enabled': enabled}
            if 'identity_key' in user:
                record.update(identity_key=identity_key, base_identity_key=state_key)
            if 'expiry_time' in user:
                record['expiry_time'] = expiry
            if index == 0 and 'metadata' in user:
                record['metadata'] = dict(metadata)
            result.append(record)
    return result


def main():
    module = AnsibleModule(argument_spec={
        'users': {'type': 'list', 'elements': 'dict', 'required': True},
        'exits': {'type': 'list', 'elements': 'str', 'required': True},
    }, supports_check_mode=True)
    try:
        module.exit_json(changed=False, expanded_users=expand(module.params['users'], module.params['exits']))
    except ExpansionError as error:
        module.fail_json(msg=str(error))


if __name__ == '__main__':
    main()
