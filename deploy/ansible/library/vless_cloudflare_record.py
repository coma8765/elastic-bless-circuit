#!/usr/bin/python
# SPDX-License-Identifier: Apache-2.0
"""Reconcile one DNS-only A record using an on-host Certbot Cloudflare token."""
import configparser
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r'''
---
module: vless_cloudflare_record
short_description: Reconcile exactly one DNS-only Cloudflare A record
options:
  zone:
    type: str
    required: true
  name:
    type: str
    required: true
  ipv4:
    type: str
    required: true
  credentials_file:
    type: path
    required: true
notes:
  - Reads dns_cloudflare_api_token from an existing on-host Certbot credentials file.
  - Never returns the token or raw API errors.
  - Refuses conflicting AAAA/CNAME records or multiple A records rather than deleting them.
'''


class APIError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise APIError('Cloudflare redirects are refused')


def main():
    m = AnsibleModule(argument_spec={
        'zone': {'type': 'str', 'required': True},
        'name': {'type': 'str', 'required': True},
        'ipv4': {'type': 'str', 'required': True},
        'credentials_file': {'type': 'path', 'required': True},
    }, supports_check_mode=True)
    try:
        zone, name = m.params['zone'].lower(), m.params['name'].lower()
        pattern = r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?'
        if not re.fullmatch(pattern, name) or not re.fullmatch(pattern, zone) or not name.endswith('.' + zone):
            raise APIError('name must be a subdomain of the specified zone')
        address = str(ipaddress.IPv4Address(m.params['ipv4']))
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string('[cloudflare]\n' + Path(m.params['credentials_file']).read_text())
        token = parser['cloudflare'].get('dns_cloudflare_api_token', '').strip().strip('\"\'')
        if not token:
            raise APIError('existing credentials file has no Cloudflare API token')
        opener = urllib.request.build_opener(NoRedirect())

        def call(path, method='GET', body=None):
            headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
            data = json.dumps(body).encode() if body is not None else None
            request = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
                                             data=data, headers=headers, method=method)
            try:
                with opener.open(request, timeout=20) as response:
                    result = json.loads(response.read(2 * 1024 * 1024 + 1))
            except urllib.error.HTTPError as error:
                raise APIError('Cloudflare request failed with HTTP ' + str(error.code))
            except (OSError, ValueError):
                raise APIError('Cloudflare request failed')
            if not result.get('success'):
                codes = ','.join(str(e.get('code')) for e in result.get('errors', []))
                raise APIError('Cloudflare rejected request; error codes: ' + codes)
            return result['result']

        verified = call('/user/tokens/verify')
        if verified.get('status') != 'active':
            raise APIError('Cloudflare API token is not active')
        zones = call('/zones?' + urllib.parse.urlencode({'name': zone, 'status': 'active', 'per_page': 2}))
        if len(zones) != 1:
            raise APIError('expected exactly one active accessible zone')
        base = '/zones/' + zones[0]['id'] + '/dns_records'
        records = call(base + '?' + urllib.parse.urlencode({'name': name, 'per_page': 100}))
        if any(r['type'] in ('AAAA', 'CNAME') for r in records):
            raise APIError('conflicting AAAA/CNAME exists; no records were changed')
        entries = [r for r in records if r['type'] == 'A']
        if len(entries) > 1:
            raise APIError('multiple A records exist; no records were changed')
        desired = {'type': 'A', 'name': name, 'content': address, 'proxied': False, 'ttl': 1}
        changed = not entries or any(entries[0].get(k) != v for k, v in desired.items())
        if changed and not m.check_mode:
            call(base + ('/' + entries[0]['id'] if entries else ''),
                 'PUT' if entries else 'POST', desired)
        m.exit_json(changed=changed, record={'name': name, 'type': 'A', 'content': address, 'proxied': False})
    except (APIError, ValueError, OSError, configparser.Error) as error:
        m.fail_json(msg=str(error) if isinstance(error, APIError) else 'invalid DNS parameters or unreadable credentials file')


if __name__ == '__main__':
    main()
