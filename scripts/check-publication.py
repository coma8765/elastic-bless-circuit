#!/usr/bin/env python3
"""Check the complete Git index before committing or publishing.

Only indexed blobs are inspected. Ignored/untracked deployment state is never
read. Findings contain a path and rule name, never matched credential contents.
This is a conservative repository guard, not a substitute for secret scanning.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

MAX_FILE_BYTES = 5 * 1024 * 1024
PRIVATE_COMPONENTS = {'.local', '.ssh', '.venv', 'venv', 'secrets', '__pycache__',
                      'build', 'node_modules', '.terraform'}
PRIVATE_SUFFIXES = {'.pyc', '.pyo', '.o', '.a', '.so', '.dylib', '.dll', '.exe',
                    '.zip', '.tar', '.tgz', '.7z', '.qcow2', '.img', '.db',
                    '.sqlite', '.sqlite3', '.log', '.key', '.pem', '.crt', '.p12', '.pfx', '.kdbx'}
PATTERNS = [
    ('PEM private key', re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')),
    ('GitHub credential', re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{70,})\b')),
    ('mesh enrollment/API credential', re.compile(rb'\b(?:tskey|hskey)-(?:auth|api)-[A-Za-z0-9_-]{20,}\b')),
    ('OpenAI credential', re.compile(rb'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}\b')),
    ('AWS access key', re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('Slack credential', re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{25,}\b')),
    ('live payment credential', re.compile(rb'\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b')),
    ('personal absolute home path', re.compile(rb'(?:/Users/|/home/)[A-Za-z0-9._-]+/')),
    ('personal Windows home path', re.compile(rb'[A-Za-z]:[\\/]Users[\\/][A-Za-z0-9._-]+[\\/]')),
]


class GuardError(Exception):
    pass


def git(repo, *args, data=None):
    # -C must select the requested repository, including isolated self-tests;
    # inherited alternate-index/worktree variables must not redirect writes.
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    result = subprocess.run(['git', '-C', str(repo), *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    if result.returncode:
        raise GuardError('Git index could not be inspected; initialize the repository and stage intended public files first')
    return result.stdout


def path_rule(path):
    parts = PurePosixPath(path).parts
    if any(part in PRIVATE_COMPONENTS for part in parts):
        return 'private state, dependency or build directory'
    name = parts[-1] if parts else ''
    if name in ('.DS_Store', 'Thumbs.db'):
        return 'machine metadata'
    if name == '.env' or (name.startswith('.env.') and name not in ('.env.example', '.env.sample')):
        return 'environment credential file'
    if name.startswith('inventory.') and name not in ('inventory.example.yml', 'inventory.local.yml'):
        return 'private deployment inventory override'
    if PurePosixPath(name).suffix.lower() in PRIVATE_SUFFIXES:
        return 'private, generated or binary artifact extension'
    return None


def inspect_index(repo, max_file_bytes=MAX_FILE_BYTES):
    entries = []
    for record in git(repo, 'ls-files', '--stage', '-z').split(b'\0'):
        if not record:
            continue
        metadata, raw_path = record.split(b'\t', 1)
        mode, oid, stage = metadata.decode('ascii').split()
        entries.append((mode, oid, stage, raw_path.decode('utf-8', errors='surrogateescape')))
    if not entries:
        raise GuardError('Git index is empty; stage the intended public files first')
    findings = []
    object_ids = sorted({entry[1] for entry in entries})
    checks = git(repo, 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)',
                 data=('\n'.join(object_ids) + '\n').encode('ascii'))
    sizes = {}
    for line in checks.decode('ascii').splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise GuardError('Git index references a missing or invalid object')
        sizes[fields[0]] = (fields[1], int(fields[2]))
    scanned = {}
    for mode, oid, stage, path in entries:
        if stage != '0':
            findings.append((path, 'unresolved merge entry'))
            continue
        reason = path_rule(path)
        if reason:
            findings.append((path, reason))
        object_type, size = sizes[oid]
        if mode == '160000' or object_type != 'blob':
            findings.append((path, 'submodule/non-blob cannot be audited by this guard'))
            continue
        if size > max_file_bytes:
            findings.append((path, 'indexed blob exceeds publication size limit'))
            continue
        if oid not in scanned:
            scanned[oid] = git(repo, 'cat-file', 'blob', oid)
        content = scanned[oid]
        if mode == '120000':
            target = content.decode('utf-8', errors='surrogateescape')
            if PurePosixPath(target).is_absolute() or '..' in PurePosixPath(target).parts or path_rule(target):
                findings.append((path, 'symlink points outside public source paths'))
        for name, pattern in PATTERNS:
            if pattern.search(content):
                findings.append((path, name))
        if path.startswith('.github/workflows/'):
            if re.search(rb'\bpull_request_target\b', content):
                findings.append((path, 'privileged pull_request_target workflow requires separate security review'))
            if re.search(rb'permissions\s*:\s*write-all\b', content):
                findings.append((path, 'workflow grants write-all permissions'))
    return len(entries), findings


def self_test():
    with tempfile.TemporaryDirectory(prefix='vless-publication-guard-') as directory:
        repo = Path(directory)
        git(repo, 'init', '--quiet')
        safe = repo / 'README.md'
        safe.write_text('Public documentation without credentials.\n')
        git(repo, 'add', '--', 'README.md')
        assert inspect_index(repo)[1] == []
        # A dirty working tree cannot hide an unsafe version already in the index.
        fixtures = [
            ('bad.py', ('ghp_' + 'x' * 36).encode(), 'GitHub credential'),
            ('bad.py', ('hskey-' + 'auth-' + 'x' * 40).encode(), 'mesh enrollment/API credential'),
            ('bad.py', ('tskey-' + 'api-' + 'x' * 40).encode(), 'mesh enrollment/API credential'),
            ('bad.py', ('-----BEGIN ' + 'PRIVATE KEY-----\n').encode(), 'PEM private key'),
            ('bad.py', ('path=' + '/Users/' + 'example-person' + '/project').encode(), 'personal absolute home path'),
            ('.local/users.json', b'{}', 'private state, dependency or build directory'),
            ('.env', b'PASSWORD=example', 'environment credential file'),
            ('private.key', b'not-a-real-key', 'private, generated or binary artifact extension'),
            ('inventory.production.yml', b'all: {}', 'private deployment inventory override'),
            ('.github/workflows/unsafe.yml', b'on: pull_request_target\npermissions: write-all\n', 'workflow grants write-all permissions'),
        ]
        for path, content, expected in fixtures:
            fixture = repo / path
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_bytes(content)
            git(repo, 'add', '--', path)
            fixture.write_text('Locally replaced after staging.\n')
            _, findings = inspect_index(repo)
            assert any(name == expected for _, name in findings), 'synthetic indexed violation was not detected'
            rendered = '\n'.join(reason for _, reason in findings)
            assert content.decode('utf-8') not in rendered, 'finding exposed indexed content'
            git(repo, 'rm', '--cached', '--force', '--', path)
            fixture.unlink()
        # Size checks apply to the staged object, independently of current files.
        fixture = repo / 'oversized.txt'
        fixture.write_text('x' * 128)
        git(repo, 'add', '--', fixture.name)
        assert any('size limit' in reason for _, reason in inspect_index(repo, 64)[1])
    print('PASS publication guard: safe index, indexed secrets/private paths, dirty-tree masking, unsafe CI and size limits')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--max-file-bytes', type=int, default=MAX_FILE_BYTES)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.max_file_bytes < 1:
        parser.error('--max-file-bytes must be positive')
    if args.self_test:
        self_test()
        return 0
    try:
        count, findings = inspect_index(args.repo, args.max_file_bytes)
    except GuardError as error:
        print('Publication check failed: ' + str(error), file=sys.stderr)
        return 2
    for path, rule in findings:
        print('BLOCK ' + json.dumps(path, ensure_ascii=True) + ': ' + rule, file=sys.stderr)
    if findings:
        print('Publication check blocked; matched content was omitted.', file=sys.stderr)
        return 1
    print('PASS publication guard: ' + str(count) + ' indexed paths; no forbidden artifacts or high-confidence credentials detected')
    return 0


if __name__ == '__main__':
    sys.exit(main())
