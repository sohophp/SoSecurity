#!/usr/bin/env python3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
composer = sys.argv[2] if len(sys.argv) > 2 else '/usr/local/bin/composer'
with tempfile.TemporaryDirectory(prefix='sosecurity-archive-') as directory:
    result = subprocess.run([runtime, composer, 'archive', '--format=zip', '--dir=' + directory,
                             '--file=sosecurity', '--no-interaction'], cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    with zipfile.ZipFile(Path(directory, 'sosecurity.zip')) as archive:
        names = archive.namelist()
        assert 'composer.json' in names and 'LICENSE' in names and 'src/Csrf/CsrfTokens.php' in names and 'resources/sql/mysql.sql' in names and 'src/Validation/Validator.php' in names and 'src/Upload/Saver.php' in names and 'src/Http/Outbound/Client.php' in names
        assert 'src/Api/HmacVerifier.php' in names and 'src/Api/ApiKeys.php' in names and 'examples/api-request.php' in names
        assert 'src/Csrf/SignedTokens.php' in names and 'src/Support/HmacKeys.php' in names and 'src/Csrf/RequestPolicy.php' in names
        assert 'examples/signed-form.php' in names and 'src/Output/HtmlCleaner.php' in names and 'examples/rich-text.php' in names
        unexpected = [name for name in names if name.startswith(('vendor/', 'tools/', 'integrations/', 'resources/api/', 'tests/', 'bin/', 'demo/', '.git/', '.github/', '.phpstan-cache/', 'var/'))]
        assert not unexpected, unexpected[:10]
        assert not any(name.endswith(('.env', '.log', 'composer.lock')) for name in names)
        print(f'PASS archive: {len(names)} package files; no vendor/development artifacts/private configuration filenames')
