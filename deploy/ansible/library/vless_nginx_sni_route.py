#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0
"""Add one explicit SNI route while preserving a pre-existing nginx stream map."""
import fcntl
import os
from pathlib import Path
import re
import subprocess
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: vless_nginx_sni_route
short_description: Add one SNI route to an explicitly selected existing nginx map
options:
  path:
    type: path
    required: true
  container:
    type: str
    required: true
  map_variable:
    type: str
    required: true
  hostname:
    type: str
    required: true
  backend:
    type: str
    required: true
notes:
  - The existing map, its default and all other entries are preserved.
  - Refuses an existing conflicting route for the requested hostname.
  - Writes in place to preserve a single-file Docker bind mount's inode.
  - Validates nginx and gracefully reloads it; rolls back the file if validation fails.
'''


class RouteError(Exception):
    pass


def main():
    m = AnsibleModule(argument_spec={
        'path': {'type': 'path', 'required': True},
        'container': {'type': 'str', 'required': True},
        'map_variable': {'type': 'str', 'required': True},
        'hostname': {'type': 'str', 'required': True},
        'backend': {'type': 'str', 'required': True},
    }, supports_check_mode=True)
    try:
        p = m.params
        if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', p['map_variable']):
            raise RouteError('invalid map variable')
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]+[a-z0-9]', p['hostname']):
            raise RouteError('invalid hostname')
        if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', p['backend']):
            raise RouteError('backend must be an explicitly selected loopback port')
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]+', p['container']):
            raise RouteError('invalid container name')

        def docker(*args):
            r = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=30)
            if r.returncode:
                raise RouteError('scoped Docker/nginx operation failed')
            return r.stdout.strip()

        before = docker('inspect', '--format', '{{.Id}} {{.State.Pid}}', p['container'])
        path = Path(p['path'])
        with path.open('r+', newline='') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            original = f.read()
            pattern = re.compile(r'(?m)^[ \t]*map\s+\$ssl_preread_server_name\s+\$' + re.escape(p['map_variable']) + r'\s*\{\s*$')
            matches = list(pattern.finditer(original))
            if len(matches) != 1:
                raise RouteError('expected exactly one selected SNI map')
            start = matches[0].end()
            end = original.find('}', start)
            if end < 0 or '{' in original[start:end]:
                raise RouteError('selected map has unsupported nesting')
            body = original[start:end]
            route = re.compile(r'(?m)^[ \t]*' + re.escape(p['hostname']) + r'\s+([^;\s]+)\s*;[^\r\n]*$')
            existing = list(route.finditer(body))
            if existing:
                if len(existing) != 1 or existing[0].group(1) != p['backend']:
                    raise RouteError('requested hostname already has a conflicting SNI route')
                m.exit_json(changed=False)
            defaults = list(re.finditer(r'(?m)^([ \t]*)default\s+[^;]+;[^\r\n]*$', body))
            if len(defaults) != 1:
                raise RouteError('expected exactly one default route')
            position = start + defaults[0].start()
            addition = defaults[0].group(1) + p['hostname'] + ' ' + p['backend'] + ';\n'
            updated = original[:position] + addition + original[position:]
            if m.check_mode:
                m.exit_json(changed=True)
            backup = path.with_name(path.name + '.vless-edge-before')
            if not backup.exists():
                fd = os.open(str(backup), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w', newline='') as out:
                    out.write(original);out.flush();os.fsync(out.fileno())
            def write(value):
                f.seek(0);f.write(value);f.truncate();f.flush();os.fsync(f.fileno())
            try:
                write(updated)
                docker('exec', p['container'], 'nginx', '-t')
                docker('exec', p['container'], 'nginx', '-s', 'reload')
            except Exception:
                write(original)
                raise
        after = docker('inspect', '--format', '{{.Id}} {{.State.Pid}}', p['container'])
        if before != after:
            raise RouteError('nginx container identity changed unexpectedly')
        m.exit_json(changed=True)
    except (RouteError, OSError, subprocess.SubprocessError) as error:
        m.fail_json(msg=str(error) if isinstance(error, RouteError) else 'could not safely update the scoped SNI route')


if __name__ == '__main__':
    main()
