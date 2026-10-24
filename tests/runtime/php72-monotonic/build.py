#!/usr/bin/env python3
"""Build a private real-clock test runtime; never install into the system PHP."""
import hashlib
import json
import shutil
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parents[2]
OUT = ROOT/'docs/state-boundary-evidence-2026-10-21'
WORK = Path(tempfile.mkdtemp(prefix='sosecurity-php72-monotonic-'))
PHP = Path('/opt/remi/php72/root/usr/bin/php')
prefix = Path(sys.argv[1]).resolve() if len(sys.argv) >= 2 else Path('/opt/remi/php72/root/usr')
scan = sys.argv[2] if len(sys.argv) == 3 else '/etc/opt/remi/php72/php.d'
if len(sys.argv) > 3:
    raise SystemExit('Use build.py [private-extracted-devel-prefix [base-ini-scan-directories]]')
tools = {}
for name in ['phpize', 'php-config']:
    original = prefix/'bin'/name
    if not original.is_file() and name == 'phpize':
        original = Path('/opt/remi/php72/root/usr/bin/phpize')
    text = original.read_text().replace('/opt/remi/php72/root/usr', str(prefix))
    if name == 'php-config':
        text = text.replace(str(prefix/'bin/php'), str(PHP))
    destination = WORK/name
    destination.write_text(text)
    destination.chmod(0o700)
    tools[name] = str(destination)
for name in ['config.m4', 'sosecurity_monotonic.c']:
    shutil.copyfile(SOURCE/name, WORK/name)
commands = [
    [tools['phpize']],
    ['./configure', '--enable-sosecurity-monotonic', '--with-php-config='+tools['php-config']],
    ['make', '-j2'],
]
report = {'purpose': 'Real CLOCK_MONOTONIC adapter for the private PHP7.2 test runtime; no SDK or system-PHP installation',
          'directory': str(WORK), 'commands': [],
          'source_sha256': {name: hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in ['config.m4', 'sosecurity_monotonic.c']}}
for index, argv in enumerate(commands):
    with (OUT/('monotonic-build-'+str(index)+'.log')).open('w') as log:
        result = subprocess.run(argv, cwd=WORK, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    report['commands'].append({'argv': argv, 'exit_code': result.returncode})
    (OUT/'monotonic-build.json').write_text(json.dumps(report, indent=2)+'\n')
    if result.returncode:
        raise SystemExit(result.returncode)
module = WORK/'modules/sosecurity_monotonic.so'
(WORK/'conf').mkdir(mode=0o700)
(WORK/'conf/monotonic.ini').write_text('extension='+str(module)+'\n')
wrapper = WORK/'php72-monotonic'
wrapper.write_text('#!/bin/bash\nexport PHP_INI_SCAN_DIR='+shlex.quote(scan+':'+str(WORK/'conf'))+'\nexec '+shlex.quote(str(PHP))+' "$@"\n')
wrapper.chmod(0o700)
report.update(wrapper=str(wrapper), module_sha256=hashlib.sha256(module.read_bytes()).hexdigest(), wrapper_sha256=hashlib.sha256(wrapper.read_bytes()).hexdigest())
(OUT/'monotonic-build.json').write_text(json.dumps(report, indent=2)+'\n')
print(str(wrapper), flush=True)
