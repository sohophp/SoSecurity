#!/usr/bin/env python3
"""Install the package through a fresh Composer path repository and execute its public API."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
composer = sys.argv[2] if len(sys.argv) > 2 else '/usr/local/bin/composer'
with tempfile.TemporaryDirectory(prefix='sosecurity-install-') as directory:
    manifest = {
        'name': 'sosecurity/integration-consumer',
        'repositories': [{'type': 'path', 'url': str(root), 'options': {'symlink': False}}],
        'require': {'sohophp/sosecurity': '@dev'},
        'config': {'allow-plugins': False}
    }
    Path(directory, 'composer.json').write_text(json.dumps(manifest))
    result = subprocess.run([runtime, composer, 'install', '--working-dir=' + directory,
                             '--no-interaction', '--no-progress'], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    Path(directory, 'verify.php').write_text('''<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';
$store = new SoSecurity\\Storage\\MemoryStore();
$csrf = new SoSecurity\\Csrf\\CsrfTokens($store);
$token = $csrf->issue('form', 'session-binding');
if (!$csrf->verify('form', 'session-binding', $token, true)
    || $csrf->verify('form', 'session-binding', $token, true)) { exit(1); }
if (!(new SoSecurity\\Validation\\Validator(['age' => ['type' => 'integer', 'min' => 18]]))->validate(['age' => 20])->valid()) { exit(3); }
if (strpos(SoSecurity\\Storage\\MySqlStore::schema(), 'ENGINE=InnoDB') === false) { exit(4); }
$rate = new SoSecurity\\RateLimit\\RateLimiter($store);
if (!$rate->consume('login', 'ip-account')->allowed) { exit(2); }
echo "PASS Composer: fresh consumer installation, PSR-4 and public API on PHP " . PHP_VERSION . "\\n";
''')
    subprocess.run([runtime, str(Path(directory, 'verify.php'))], check=True)
