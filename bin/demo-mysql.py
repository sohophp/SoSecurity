#!/usr/bin/env python3
"""Optional local demonstration database, isolated from every host MySQL service."""
import argparse
import json
import os
import secrets
import stat
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('action', choices=['start', 'stop'])
parser.add_argument('--directory', default='/var/lib/sosecurity-demo-mysql')
parser.add_argument('--config', default='/var/lib/sosecurity-demo/mysql.php')
args = parser.parse_args()
directory = Path(args.directory).absolute(); config = Path(args.config).absolute()
for path in [directory, config.parent]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise SystemExit('Run as the owner of dedicated existing 0700 directories; symlinks are refused.')
marker = directory / '.sosecurity-demo'
if marker.exists():
    if marker.read_text() != 'SoSecurity private MySQL demo v1\n': raise SystemExit('Unrecognized sandbox marker.')
elif args.action == 'start' and not any(directory.iterdir()):
    marker.write_text('SoSecurity private MySQL demo v1\n'); marker.chmod(0o600)
else: raise SystemExit('Refusing a nonempty unmarked directory.')
socket = str(directory / 'mysql.sock')
def sql(statement):
    return subprocess.run(['mysql', '--no-defaults', '--socket=' + socket, '-uroot'], input=statement,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=15)
if args.action == 'stop':
    if sql('SHUTDOWN').returncode: raise SystemExit('Private demo database was not stopped.')
    print('Private demo MySQL stopped; existing sandbox data retained.'); raise SystemExit(0)
if not (directory / 'data').exists():
    subprocess.run(['mysqld', '--no-defaults', '--datadir=' + str(directory / 'data'), '--initialize-insecure',
                    '--innodb-buffer-pool-size=32M', '--log-error=' + str(directory / 'initialize.log')], check=True, timeout=300)
if not Path(socket).exists() or sql('SELECT 1').returncode:
    subprocess.run(['mysqld', '--no-defaults', '--datadir=' + str(directory / 'data'), '--socket=' + socket,
                    '--pid-file=' + str(directory / 'mysql.pid'), '--log-error=' + str(directory / 'server.log'),
                    '--skip-networking', '--mysqlx=OFF', '--innodb-buffer-pool-size=32M', '--daemonize'], check=True, timeout=60)
access = directory / '.access.json'
if access.exists():
    password = json.loads(access.read_text())['password']
    if len(password) != 64 or any(c not in '0123456789abcdef' for c in password): raise SystemExit('Invalid sandbox access metadata.')
else:
    password = secrets.token_hex(32)
    fd = os.open(str(access), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output: json.dump({'password': password}, output)
schema = (Path(__file__).resolve().parent.parent / 'resources/sql/mysql.sql').read_text()
# A compatibility-only sandbox account; no host account or authentication policy is changed.
setup = "CREATE DATABASE IF NOT EXISTS sosecurity_demo CHARACTER SET utf8mb4 COLLATE utf8mb4_bin; USE sosecurity_demo;\n" + schema
setup += "\nCREATE USER IF NOT EXISTS 'sosecurity_demo'@'localhost' IDENTIFIED WITH mysql_native_password BY '" + password + "';"
setup += "\nGRANT SELECT,INSERT,UPDATE,DELETE ON sosecurity_demo.sosecurity_state TO 'sosecurity_demo'@'localhost';"
if sql(setup).returncode: raise SystemExit('Private demo database setup failed; no host service was accessed.')
def php_string(text): return "'" + text.replace('\\', '\\\\').replace("'", "\\'") + "'"
values = {'dsn': 'mysql:unix_socket=' + socket + ';dbname=sosecurity_demo;charset=utf8mb4', 'user': 'sosecurity_demo', 'password': password}
contents = '<?php\nreturn [\n' + ''.join('    ' + php_string(key) + ' => ' + php_string(value) + ',\n' for key, value in values.items()) + '];\n'
# Both directories are private and operator controlled; never write this config from an HTTP request.
if config.exists() and (config.is_symlink() or config.stat().st_uid != os.geteuid()): raise SystemExit('Refusing another owner\'s configuration.')
fd = os.open(str(config), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
with os.fdopen(fd, 'w') as output: output.write(contents)
config.chmod(0o600)
print('Private demo MySQL ready: no TCP listener, dedicated table and DML-only application account.')
