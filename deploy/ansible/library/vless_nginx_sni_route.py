#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0
"""Add one explicit SNI route while preserving a pre-existing nginx stream map."""
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import shlex
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
  previous_backend:
    type: str
    description: Replace one existing exact route only if it equals this expected IPv4 endpoint. Public unicast is permitted for comparison only.
  allow_private_backend:
    type: bool
    default: false
    description: Explicitly allow an IPv4 backend in RFC1918 space, in addition to 127.0.0.1.
notes:
  - The existing map, its default and all other entries are preserved.
  - Refuses an existing conflicting route unless previous_backend matches exactly; duplicate routes always fail closed.
  - Writes in place to preserve a single-file Docker bind mount's inode.
  - Validates nginx and gracefully reloads it; rolls back the file if validation fails.
'''


class RouteError(Exception):
    pass


def exact_routes(body, hostname):
    """Read map statements without changing their original spelling or layout."""
    lexer = shlex.shlex(body, posix=True, punctuation_chars=';')
    lexer.whitespace_split = True
    lexer.commenters = '#'
    statement, matches = [], []
    try:
        for token in lexer:
            if token.startswith(';') and not token.strip(';'):
                if statement and statement[0].casefold() == hostname.casefold():
                    if len(statement) != 2:
                        raise RouteError('requested hostname has an unsupported SNI route')
                    matches.append(statement[1])
                statement = []
            else:
                statement.append(token)
    except ValueError:
        raise RouteError('selected map has invalid quoting')
    if statement:
        raise RouteError('selected map has an unterminated statement')
    return matches


def replacement_span(body, hostname):
    """Locate the backend token without rewriting quotes, comments or whitespace."""
    tokens, i = [], 0
    while i < len(body):
        if body[i].isspace():
            i += 1
            continue
        if body[i] == '#':
            newline = body.find('\n', i)
            i = len(body) if newline < 0 else newline + 1
            continue
        if body[i] == ';':
            if tokens and tokens[0][0].casefold() == hostname.casefold():
                if len(tokens) != 2:
                    raise RouteError('requested hostname has an unsupported SNI route')
                return tokens[1][1:]
            tokens = []
            i += 1
            continue
        start, quote = i, None
        while i < len(body):
            char = body[i]
            if char == "\\" and quote != "'":
                i += 2
                continue
            if quote:
                if char == quote:
                    quote = None
            elif char in "\"'":
                quote = char
            elif char.isspace() or char in ';#':
                break
            i += 1
        raw = body[start:i]
        decoded = shlex.split(raw, comments=False, posix=True)
        if len(decoded) != 1:
            raise RouteError('selected map has unsupported token spelling')
        tokens.append((decoded[0], start, i))
    raise RouteError('could not locate the expected existing SNI route')


def main():
    m = AnsibleModule(argument_spec={
        'path': {'type': 'path', 'required': True},
        'container': {'type': 'str', 'required': True},
        'map_variable': {'type': 'str', 'required': True},
        'hostname': {'type': 'str', 'required': True},
        'backend': {'type': 'str', 'required': True},
        'previous_backend': {'type': 'str'},
        'allow_private_backend': {'type': 'bool', 'default': False},
    }, supports_check_mode=True)
    try:
        p = m.params
        if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]*', p['map_variable']):
            raise RouteError('invalid map variable')
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]+[a-z0-9]', p['hostname']):
            raise RouteError('invalid hostname')
        try:
            host, service = p['backend'].rsplit(':', 1)
            address = ipaddress.IPv4Address(host)
            if not re.fullmatch(r'[0-9]{1,5}', service) or not 1 <= int(service) <= 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise RouteError('backend must be IPv4:port with a port in 1..65535')
        private_ranges = tuple(ipaddress.IPv4Network(network) for network in
                               ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
        if address != ipaddress.IPv4Address('127.0.0.1') and not (
                p.get('allow_private_backend', False) and any(address in network for network in private_ranges)):
            raise RouteError('backend must be 127.0.0.1, or an explicitly enabled RFC1918 IPv4 address')
        previous = p.get('previous_backend')
        if previous is not None:
            try:
                old_host, old_port = previous.rsplit(':', 1)
                old_address = ipaddress.IPv4Address(old_host)
                if (not re.fullmatch(r'[0-9]{1,5}', old_port) or not 1 <= int(old_port) <= 65535
                        or old_address.is_unspecified or old_address.is_multicast
                        or old_address.is_reserved or old_address.is_link_local):
                    raise ValueError()
            except (ValueError, TypeError):
                raise RouteError('previous_backend must be an IPv4 unicast address and port in 1..65535')
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
            existing = exact_routes(body, p['hostname'])
            if existing:
                if len(existing) != 1:
                    raise RouteError('requested hostname has duplicate SNI routes')
                if existing[0] == p['backend']:
                    m.exit_json(changed=False)
                if previous is None or existing[0] != previous:
                    raise RouteError('requested hostname already has a conflicting SNI route')
                left, right = replacement_span(body, p['hostname'])
                updated = original[:start + left] + p['backend'] + original[start + right:]
            else:
                if previous is not None:
                    raise RouteError('expected previous SNI route is absent')
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
