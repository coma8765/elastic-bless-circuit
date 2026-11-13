#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0
"""Read only container identities and public nginx/certificate metadata."""
import hashlib
import json
import re
import shlex
import subprocess
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: vless_edge_audit
short_description: Read container identities and public nginx metadata
notes:
  - Does not inspect container environment variables or TLS private keys.
  - Returns config hashes and selected public directives, not full nginx files.
'''


def exact_server_names(content):
    """Read exact names with nginx quoting, case and multiline directives.

    Treat unsupported syntax as an audit failure rather than overlooking an
    unrelated vhost. Regexes, wildcards and variable names are not exact names.
    """
    lexer = shlex.shlex(content, posix=True, punctuation_chars=';{}')
    lexer.whitespace_split = True
    lexer.commenters = '#'
    directive, names = [], []
    for token in lexer:
        if token and all(character in ';{}' for character in token):
            for boundary in token:
                if boundary == ';' and directive and directive[0] == 'server_name':
                    names.extend(name.lower() for name in directive[1:]
                                 if name and not name.startswith(('~', '.'))
                                 and '*' not in name and '$' not in name)
                directive = []
        else:
            directive.append(token)
    return names


def main():
    m = AnsibleModule(argument_spec={}, supports_check_mode=True)
    try:
        ids = subprocess.run(['docker', 'ps', '-q'], check=True, text=True, capture_output=True).stdout.split()
        containers = {}
        for identifier in ids:
            fmt = '{{.Id}} {{.Name}} {{.State.Pid}} {{.State.StartedAt}} {{.State.Status}} {{.RestartCount}}'
            raw = subprocess.run(['docker', 'inspect', '--format', fmt, identifier],
                                 check=True, text=True, capture_output=True).stdout.strip().split()
            containers[raw[1]] = {'id': raw[0], 'pid': raw[2], 'started': raw[3], 'status': raw[4], 'restart_count': int(raw[5])}
        configs, certificates = {}, {}
        paths = set(Path('/etc/nginx/conf.d').glob('*.conf')) | set(Path('/etc/nginx/sites-enabled').glob('*'))
        for path in sorted(paths):
            if not path.is_file():
                continue
            content = path.read_bytes()
            directives = []
            server_names = exact_server_names(content.decode(errors='replace'))
            for line in content.decode(errors='replace').splitlines():
                match = re.match(r'^\s*(listen|server_name|ssl_certificate)\s+([^;]+);', line)
                if match:
                    directives.append(match.group(1) + ' ' + match.group(2))
                    if match.group(1) == 'ssl_certificate':
                        certificate = Path(match.group(2).strip('"\''))
                        if certificate.is_file():
                            certificates[str(certificate)] = hashlib.sha256(certificate.read_bytes()).hexdigest()
            configs[str(path)] = {'sha256': hashlib.sha256(content).hexdigest(), 'directives': directives, 'server_names': server_names}
        pid = Path('/run/nginx.pid').read_text().strip()
        m.exit_json(changed=False, audit={'containers': containers, 'nginx_configs': configs,
                                       'certificate_hashes': certificates, 'nginx_master_pid': pid})
    except (OSError, subprocess.SubprocessError, IndexError, ValueError):
        m.fail_json(msg='could not collect scoped Docker/nginx audit metadata')


if __name__ == '__main__':
    main()
