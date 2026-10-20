#!/usr/bin/env python3
"""Exercise managed authentication and restoration from a fresh package copy."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
composer = sys.argv[2] if len(sys.argv) > 2 else '/usr/local/bin/composer'
suites = ['factory', 'operations-notices', 'enrollment-notices', 'notice-queue-rotation', 'resolution-notices', 'migration-notices', 'revocation-notices', 'recovery-notices', 'recovery-terminal-notices', 'restoration', 'restoration-notices', 'restoration-cleanup-notices', 'restoration-lifecycle', 'restoration-authentication',
          'restoration-maintenance-durability']

with tempfile.TemporaryDirectory(prefix='sosecurity-factor-consumer-') as directory:
    consumer = Path(directory)
    manifest = {
        'name': 'sosecurity/managed-factor-consumer',
        'repositories': [{'type': 'path', 'url': str(root), 'options': {'symlink': False}}],
        'require': {'sohophp/sosecurity': '@dev'},
        'config': {'allow-plugins': False},
    }
    (consumer / 'composer.json').write_text(json.dumps(manifest))
    install = subprocess.run(
        [runtime, composer, 'install', '--working-dir=' + directory,
         '--no-interaction', '--no-progress'], capture_output=True, text=True)
    if install.returncode:
        raise RuntimeError(install.stdout + install.stderr)
    package = consumer / 'vendor/sohophp/sosecurity'
    if package.is_symlink() or not (package / 'src/Account/FactorRestoration.php').is_file():
        raise RuntimeError('Expected an independent installed package copy.')
    # Tests are external to the distributed package. Their relative imports use
    # only this consumer autoloader and the examples/resources actually installed.
    shutil.copytree(root / 'tests', consumer / 'tests',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in ['examples', 'resources']:
        (consumer / name).symlink_to(package / name, target_is_directory=True)
    probe = consumer / 'installed-source.php'
    probe.write_text('''<?php
require __DIR__.'/vendor/autoload.php';
$actual = (new ReflectionClass(SoSecurity\\Account\\FactorRestoration::class))->getFileName();
if (realpath($actual) !== realpath(__DIR__.'/vendor/sohophp/sosecurity/src/Account/FactorRestoration.php')) {
    throw new RuntimeException('Restoration did not load from the installed package.');
}
$factory = (new ReflectionClass(SoSecurity\\Security::class))->getFileName();
if (realpath($factory) !== realpath(__DIR__.'/vendor/sohophp/sosecurity/src/Security.php')) {
    throw new RuntimeException('Managed authentication factory did not load from the installed package.');
}
echo "PASS installed managed factor source isolation\\n";
''')
    subprocess.run([runtime, str(probe)], cwd=consumer, check=True)
    for name in suites:
        subprocess.run([runtime, '-d', 'memory_limit=8M',
                        str(consumer / 'tests/account-factor' / (name + '.php'))],
                       cwd=consumer, check=True)
    subprocess.run([runtime, '-d', 'memory_limit=8M',
                    str(consumer / 'tests/account-factor-notices.php')],
                   cwd=consumer, check=True)
    subprocess.run(['python3', str(consumer / 'tests/account_factor_smtp.py'), runtime],
                   cwd=consumer, check=True)
    print('PASS installed managed factors: ' + str(len(suites)) +
          ' suites plus MFA notification lifecycle and local TLS SMTP, owned temporary SQLite only; no SDK worktree autoloader', flush=True)
