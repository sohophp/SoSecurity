#!/usr/bin/env python3
"""Provision and stop a private no-TCP MySQL instance. Never reads host credentials or tables."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
with tempfile.TemporaryDirectory(prefix='sosecurity-mysql-') as directory:
    data = str(Path(directory, 'data')); socket = str(Path(directory, 'mysql.sock'))
    # MySQL 8's initialization can use >100 MiB of redo. A 16 MiB ring stalls on repeated rotation.
    # Keep this test-only instance bounded, but large enough to initialize under the existing 180s limit.
    common = ['mysqld', '--no-defaults', '--datadir=' + data, '--innodb-buffer-pool-size=32M', '--innodb-log-file-size=64M']
    if os.geteuid() == 0: common.append('--user=root')
    subprocess.run([*common, '--initialize-insecure', '--log-error=' + str(Path(directory, 'init.log'))], check=True, timeout=180)
    log = open(Path(directory, 'launcher.log'), 'w+')
    server = subprocess.Popen([*common, '--socket=' + socket, '--pid-file=' + str(Path(directory, 'mysql.pid')),
                               '--log-error=' + str(Path(directory, 'server.log')), '--skip-networking', '--mysqlx=OFF'], stdout=log, stderr=log)
    def sql(text):
        return subprocess.run(['mysql', '--no-defaults', '--socket=' + socket, '-uroot', '-e', text], capture_output=True, text=True, timeout=3)
    try:
        for _ in range(150):
            if server.poll() is not None: raise RuntimeError('Isolated MySQL exited; inspect its private log')
            try:
                if sql('SELECT 1').returncode == 0: break
            except subprocess.TimeoutExpired: pass
            time.sleep(.1)
        else: raise RuntimeError('Isolated MySQL startup timeout')
        setup = sql("CREATE DATABASE sosecurity_test CHARACTER SET utf8mb4 COLLATE utf8mb4_bin; CREATE USER 'sosecurity_test'@'localhost' IDENTIFIED WITH mysql_native_password BY 'integration-only'; GRANT ALL ON sosecurity_test.* TO 'sosecurity_test'@'localhost';")
        if setup.returncode: raise RuntimeError('Isolated MySQL account setup failed')
        env = os.environ.copy(); env['SOSECURITY_TEST_MYSQL_SOCKET'] = socket
        subprocess.run([runtime, str(root / 'tests/mysql.php')], env=env, check=True)
        subprocess.run([runtime, str(root / 'tests/api.php')], env=env, check=True)
        subprocess.run([runtime, str(root / 'tests/concurrency.php')], env=env, check=True)
    finally:
        if server.poll() is None:
            sql('SHUTDOWN')
            try: server.wait(timeout=10)
            except subprocess.TimeoutExpired: server.terminate(); server.wait(timeout=5)
        log.close()
