#!/usr/bin/env python3
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate an isolated signed root/com/example.com hierarchy for ACME tests.

Security-sensitive test infrastructure. Generated keys are private fixture keys,
not public DNS root anchors. Neither the host resolver nor system trust changes.
"""

import argparse
from pathlib import Path
import re
import subprocess


SCENARIOS = ('secure-allow', 'secure-deny', 'bogus', 'insecure', 'alias-negative')


def run(*args, cwd):
    result = subprocess.run(args, cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stdout}')
    return result.stdout.strip()


def zone_text(zone, body):
    return (f'$ORIGIN {zone}\n$TTL 60\n'
            '@ IN SOA ns.example.com. hostmaster.example.com. (1 60 60 300 60)\n'
            '@ IN NS ns.example.com.\n' + body)


def prepare(directory, domain, scenario):
    if not re.fullmatch(r'[a-z0-9-]+\.example\.com', domain):
        raise ValueError('DNSSEC fixture requires a single label under example.com')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = directory.resolve()
    keys = directory / 'keys'
    keys.mkdir(mode=0o700, exist_ok=True)
    key_names = {}
    for zone, basename in (('.', 'root'), ('com.', 'com'), ('example.com.', 'example')):
        marker = keys / (basename + '.name')
        if not marker.exists():
            name = run('dnssec-keygen', '-q', '-a', 'ECDSAP256SHA256', '-f', 'KSK',
                       '-K', str(keys), zone, cwd=directory)
            marker.write_text(name + '\n')
        key_names[zone] = marker.read_text().strip()

    def ds(zone):
        return run('dnssec-dsfromkey', '-2', str(keys / (key_names[zone] + '.key')),
                   cwd=directory) + '\n'

    def sign(zone, basename, text):
        unsigned = directory / (basename + '.zone')
        unsigned.write_text(text)
        signed = directory / (basename + '.signed')
        # One combined signing key per fixture zone, not a rollover simulation.
        run('dnssec-signzone', '-n', '1', '-z', '-S', '-K', str(keys), '-o', zone,
            '-s', 'now-3600', '-e', 'now+86400', '-f', str(signed),
            str(unsigned), cwd=directory)
        return signed

    root = sign('.', 'root', zone_text('.', 'com. IN NS ns.example.com.\n'
                                      'ns.example.com. IN A 127.0.0.1\n' + ds('com.')))
    parent_body = 'example.com. IN NS ns.example.com.\nns.example.com. IN A 127.0.0.1\n'
    if scenario != 'insecure':
        parent_body += ds('example.com.')
    parent = sign('com.', 'com', zone_text('com.', parent_body))
    issuer = 'other-ca.example.com' if scenario in ('secure-deny', 'bogus') else 'ca.example.com'
    body = 'ns IN A 127.0.0.1\n'
    if scenario == 'alias-negative':
        body += (f'{domain}. IN CNAME target.example.com.\n'
                 'target IN A 127.0.0.1\n@ IN CAA 0 issue "ca.example.com"\n')
    else:
        body += f'{domain}. IN CAA 0 issue "{issuer}"\n'
    if scenario == 'insecure':
        child = directory / 'example.unsigned'
        child.write_text(zone_text('example.com.', body))
    else:
        child = sign('example.com.', 'example', zone_text('example.com.', body))
    if scenario == 'bogus':
        # Change signed RDATA after signing. DNSKEY and DS links remain valid.
        text = child.read_text()
        if text.count('"other-ca.example.com"') != 1:
            raise ValueError('Expected exactly one signed CAA property to corrupt')
        child.write_text(text.replace('"other-ca.example.com"', '"ca.example.com"'))

    (directory / 'root.ds').write_text(ds('.'))
    config = f'''options {{
    directory "{directory}";
    listen-on port 1054 {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    recursion no;
    dnssec-validation no;
    pid-file "{directory}/named.pid";
    session-keyfile "{directory}/session.key";
}};
controls {{ }};
zone "." {{ type primary; file "{root}"; }};
zone "com" {{ type primary; file "{parent}"; }};
zone "example.com" {{ type primary; file "{child}"; }};
'''
    (directory / 'named.conf').write_text(config)
    (directory / 'unbound.conf').write_text(f'''server:
    interface: 127.0.0.1@1053
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    directory: "{directory}"
    pidfile: "{directory}/unbound.pid"
    use-syslog: no
    verbosity: 1
    val-log-level: 2
    ede: yes
    module-config: "validator iterator"
    trust-anchor-file: "{directory}/root.ds"
    val-permissive-mode: no
    do-not-query-localhost: no
    tcp-upstream: yes
    qname-minimisation: no
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@1054
    forward-first: no
''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--domain', default='pki.example.com')
    parser.add_argument('--scenario', choices=SCENARIOS, required=True)
    args = parser.parse_args()
    prepare(args.directory, args.domain, args.scenario)


if __name__ == '__main__':
    main()
