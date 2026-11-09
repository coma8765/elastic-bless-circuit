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


def expand(users, exits):
    if not isinstance(exits, list) or not exits or any(not valid_name(name) for name in exits):
        raise ExpansionError('exits must be a nonempty list of valid inventory names')
    if len(set(exits)) != len(exits):
        raise ExpansionError('exit inventory names must be unique')
    if not isinstance(users, list):
        raise ExpansionError('users must be a list')
    result, emails = [], set()
    for user in users:
        if not isinstance(user, dict) or not valid_name(user.get('email')):
            raise ExpansionError('users require valid email labels of at most 64 characters')
        primary, additional = user.get('exit'), user.get('additional_exits', [])
        if not valid_name(primary) or primary not in exits:
            raise ExpansionError('each user exit must name a configured exit')
        if not isinstance(additional, list) or any(not valid_name(name) for name in additional):
            raise ExpansionError('additional_exits must be a list of valid exit inventory names')
        if len(set(additional)) != len(additional) or primary in additional:
            raise ExpansionError('additional_exits must be unique and exclude the primary exit')
        if any(name not in exits for name in additional):
            raise ExpansionError('additional_exits must name configured exits')
        enabled = user.get('enabled', True)
        if not isinstance(enabled, bool):
            raise ExpansionError('user enabled must be a boolean')
        for index, exit_name in enumerate([primary] + additional):
            email = user['email'] if index == 0 else user['email'] + '--' + exit_name
            if not valid_name(email):
                raise ExpansionError('derived email labels must be at most 64 characters')
            if email in emails:
                raise ExpansionError('base and derived user emails must be globally unique')
            emails.add(email)
            result.append({'email': email, 'base_email': user['email'],
                           'exit': exit_name, 'enabled': enabled})
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
