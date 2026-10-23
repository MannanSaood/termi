#!/usr/bin/env python3
"""Actual isolated Linux APT download check. Installs/executes no packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--keyring', type=Path, required=True)
    args = parser.parse_args()
    base = args.url.rstrip('/')
    with urllib.request.urlopen(base + '/approved-packages.json', timeout=15) as response:
        manifest = json.load(response)
    with tempfile.TemporaryDirectory(prefix='termi-local-apt-') as folder:
        root = Path(folder)
        for directory in ['etc/apt.conf.d', 'etc/preferences.d', 'state/lists/partial', 'cache/archives/partial', 'log', 'downloads']:
            (root / directory).mkdir(parents=True)
        (root / 'state/status').write_text('')
        (root / 'etc/apt.conf').write_text('')
        (root / 'etc/sources.list').write_text(f'deb [arch=aarch64 signed-by={args.keyring.resolve()}] {base} stable main\n')
        config = root / 'isolated.conf'
        config.write_text(f'Dir::Etc "{root / "etc"}";\n#clear APT::Architectures;\nAPT::Architecture "aarch64";\nAPT::Architectures {{ "aarch64"; }};\n')
        env = {**os.environ, 'APT_CONFIG': str(config), 'LC_ALL': 'C'}
        apt = ['apt-get', '-o', f'Dir::State={root / "state"}', '-o', f'Dir::State::status={root / "state/status"}',
               '-o', f'Dir::Cache={root / "cache"}', '-o', f'Dir::Log={root / "log"}', '-o', 'APT::Sandbox::User=builder',
               '-o', 'Acquire::Languages=none', '-o', 'APT::Update::Error-Mode=any', '-o', 'Acquire::Retries=0',
               '-o', 'Acquire::http::Timeout=15', '-o', 'Acquire::AllowInsecureRepositories=false', '-o', 'APT::Get::AllowUnauthenticated=false']
        subprocess.run(apt + ['update'], env=env, check=True)
        # Exercise both ordinary and Debian epoch filenames against real APT.
        subprocess.run(apt + ['download', 'hello', 'openssl', 'termux-exec'], env=env, cwd=root / 'downloads', check=True)
        expected = {r['sha256'] for r in manifest['packages'] if r['name'] in ('hello', 'openssl', 'termux-exec')}
        actual = set()
        for file in (root / 'downloads').glob('*.deb'):
            with file.open('rb') as stream:
                actual.add(hashlib.file_digest(stream, 'sha256').hexdigest())
        if actual != expected or len(actual) != 3:
            raise ValueError('Downloaded package bytes differ from repository inventory')
        print(json.dumps(dict(result='PASS', downloaded=3, installed=0, executed=0, url=base)))


if __name__ == '__main__':
    main()
