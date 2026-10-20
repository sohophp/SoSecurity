#!/usr/bin/env python3
"""Provision and stop a private no-TCP MySQL instance. Never reads host credentials or tables."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
root = Path(__file__).resolve().parent.parent
matrix = len(sys.argv)>1 and sys.argv[1]=='--matrix'
webhook_inbox = len(sys.argv)>1 and sys.argv[1]=='--webhook-inbox'
webhook_processing = len(sys.argv)>1 and sys.argv[1]=='--webhook-processing'
idempotency = len(sys.argv)>1 and sys.argv[1]=='--idempotency'
sql_enlistment = len(sys.argv)>1 and sys.argv[1]=='--sql-enlistment'
sql_dependencies = len(sys.argv)>1 and sys.argv[1]=='--sql-dependencies'
accounts_only = len(sys.argv)>1 and sys.argv[1]=='--accounts'
outbox = len(sys.argv)>1 and sys.argv[1]=='--outbox'
quarantine = len(sys.argv)>1 and sys.argv[1]=='--quarantine'
quarantine_clam = len(sys.argv)>1 and sys.argv[1]=='--quarantine-clam'
outbox_concurrency = len(sys.argv)>1 and sys.argv[1]=='--outbox-concurrency'
outbox_reconciliation = len(sys.argv)>1 and sys.argv[1]=='--outbox-reconciliation'
account_factors = len(sys.argv)>1 and sys.argv[1]=='--account-factors'
factor_notices = len(sys.argv)>1 and sys.argv[1]=='--factor-notices'
restoration_cleanup_notices = len(sys.argv)>1 and sys.argv[1]=='--restoration-cleanup-notices'
recovery_notices = len(sys.argv)>1 and sys.argv[1]=='--recovery-notices'
recovery_terminal_notices = len(sys.argv)>1 and sys.argv[1]=='--recovery-terminal-notices'
migration_notices = len(sys.argv)>1 and sys.argv[1]=='--migration-notices'
remaining_factor_notices = len(sys.argv)>1 and sys.argv[1]=='--remaining-factor-notices'
notice_queue_rotation = len(sys.argv)>1 and sys.argv[1]=='--notice-queue-rotation'
snapshots = len(sys.argv)>1 and sys.argv[1]=='--snapshots'
webauthn = len(sys.argv)>1 and sys.argv[1]=='--webauthn'
oidc_process = len(sys.argv)>1 and sys.argv[1]=='--oidc-process'
audit_metrics = len(sys.argv)>1 and sys.argv[1]=='--audit-metrics'
audit_alert = len(sys.argv)>1 and sys.argv[1]=='--audit-alert'
runtimes = sys.argv[2:] if accounts_only or matrix or webhook_inbox or webhook_processing or idempotency or sql_enlistment or sql_dependencies or outbox or quarantine or quarantine_clam or outbox_concurrency or outbox_reconciliation or account_factors or factor_notices or restoration_cleanup_notices or recovery_notices or recovery_terminal_notices or migration_notices or remaining_factor_notices or notice_queue_rotation or snapshots or webauthn or oidc_process or audit_metrics or audit_alert else sys.argv[1:]
if not runtimes: runtimes=['php']
def ownership(runtime, env, modes):
    for mode in modes:
        subprocess.run([runtime, str(root / 'tests/webhook-processing-ownership.php'), 'mysql', mode], env=env, check=True)
        subprocess.run([runtime, str(root / 'tests/webhook-processing-ownership.php'), 'mysql', mode, 'implicit'], env=env, check=True)
def account_suites(runtime, env):
    if subprocess.run([runtime, '-r', 'exit(extension_loaded("sodium") ? 0 : 1);'], env=env, check=False).returncode:
        print('NOT RUN account lifecycle MySQL: sodium unavailable', flush=True)
        if env.get('SOSECURITY_REQUIRE_CRYPTO')=='1': raise RuntimeError('Required account crypto is unavailable')
        return
    for test in ['mailbox-recovery', 'mailbox-recovery-approvals', 'mailbox-recovery-safety', 'mailbox-recovery-maintenance', 'mailbox-recovery-dispatch', 'mailbox-recovery-factory', 'mailbox-recovery-concurrency', 'account-dispatch', 'account-mail-factory', 'account-recovery', 'account-recovery-maintenance', 'account-recovery-factory', 'account-recovery-clock', 'account-recovery-concurrency', 'account-budget-sql', 'account-factory', 'account-ledger-mysql', 'registration-authority', 'account-request-budget', 'registration', 'registration-capacity', 'registration-maintenance', 'registration-ledger-maintenance', 'address-lock-order', 'address-change-maintenance', 'address-change']:
        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests'/(test+'.php')), 'mysql'], env=env, check=True)
    subprocess.run(['python3', str(root/'tests/account_mail_pipeline_mysql.py'), runtime], env=env, check=True)
    subprocess.run(['python3', str(root/'tests/account_change_concurrency.py'), runtime, 'mysql'], env=env, check=True)
with tempfile.TemporaryDirectory(prefix='sosecurity-mysql-') as directory:
    Path(directory,'account-test-owner').write_text('owned SDK account SQL test\n')
    owner = os.urandom(16).hex() if quarantine or quarantine_clam else None
    if owner is not None:
        marker = Path(directory, 'quarantine-backend-owner')
        marker.write_text(owner)
        marker.chmod(0o600)
    if snapshots or quarantine or quarantine_clam: print('OWNED_INSTANCE '+directory,flush=True)
    data = str(Path(directory, 'data')); socket = str(Path(directory, 'mysql.sock'))
    # MySQL 8's initialization can use >100 MiB of redo. A 16 MiB ring stalls on repeated rotation.
    # Keep this test-only instance bounded, but large enough to initialize under the existing 180s limit.
    # Private disposable instance: trigger fault injection must not require SUPER or alter production grants.
    common = ['mysqld', '--no-defaults', '--skip-log-bin', '--datadir=' + data, '--innodb-buffer-pool-size=32M', '--innodb-log-file-size=64M']
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
        env = os.environ.copy()
        if oidc_process:
            env = {key: value for key, value in env.items() if not key.startswith('SOSECURITY_TEST_')}
        env['SOSECURITY_TEST_MYSQL_SOCKET'] = socket; env['SOSECURITY_TEST_ROOT']=str(root)
        if quarantine or quarantine_clam:
            env['SOSECURITY_TEST_QUARANTINE_OWNER'] = owner
            env['SOSECURITY_TEST_QUARANTINE_NAMESPACE'] = 'quarantine-' + os.urandom(8).hex()
        if matrix:
            # One private server reused sequentially. Each suite resets its test schema; there are no concurrent suites.
            # Prepare the table before check.sh's early API contract, then let mysql.php run its full schema tests.
            install='require getenv("SOSECURITY_TEST_ROOT")."/vendor/autoload.php"; $pdo=new PDO("mysql:unix_socket=".getenv("SOSECURITY_TEST_MYSQL_SOCKET").";dbname=sosecurity_test;charset=utf8mb4","sosecurity_test","integration-only",[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]); SoSecurity\\Storage\\MySqlStore::install($pdo);'
            subprocess.run([runtimes[0],'-r',install],env=env,check=True)
            for runtime in runtimes:
                print('BEGIN full isolated matrix: '+runtime,flush=True)
                subprocess.run([str(root/'bin/check.sh'),runtime],cwd=root,env=env,check=True)
                print('PASS full isolated matrix: '+runtime,flush=True)
        else:
            oidc_installed = False
            for runtime in runtimes:
                if oidc_process:
                    autoload = env.get('SOSECURITY_OIDC_AUTOLOAD')
                    if not autoload or not Path(autoload).is_file():
                        raise RuntimeError('SOSECURITY_OIDC_AUTOLOAD must name the local Composer consumer autoload.php')
                    if not oidc_installed:
                        install = 'require getenv("SOSECURITY_TEST_ROOT")."/vendor/autoload.php"; $pdo=new PDO("mysql:unix_socket=".getenv("SOSECURITY_TEST_MYSQL_SOCKET").";dbname=sosecurity_test;charset=utf8mb4","sosecurity_test","integration-only",[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]); SoSecurity\\Storage\\MySqlStore::install($pdo);'
                        subprocess.run([runtime, '-r', install], env=env, check=True)
                        oidc_installed = True
                    subprocess.run(['python3', str(root / 'integrations/oidc/tests/process_race.py'), autoload, runtime], env=env, check=True)
                    subprocess.run([runtime, str(root / 'integrations/oidc/tests/sessions.php'), autoload, 'mysql'], env=env, check=True)
                    continue
                if audit_metrics:
                    install = 'require getenv("SOSECURITY_TEST_ROOT")."/vendor/autoload.php"; $pdo=new PDO("mysql:unix_socket=".getenv("SOSECURITY_TEST_MYSQL_SOCKET").";dbname=sosecurity_test;charset=utf8mb4","sosecurity_test","integration-only",[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]); SoSecurity\\Storage\\MySqlStore::install($pdo);'
                    subprocess.run([runtime, '-r', install], env=env, check=True)
                    subprocess.run(['python3', str(root/'tests/audit_metrics_process.py'), runtime, 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-metrics-fault.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-recent-events.php'), 'mysql'], env=env, check=True)
                    subprocess.run(['python3', str(root/'tests/audit_recent_process.py'), runtime, 'mysql'], env=env, check=True)
                    continue
                if audit_alert:
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-alert-outbox.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-alert-retained.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-alert-worker.php'), 'mysql'], env=env, check=True)
                    continue
                if webauthn:
                    autoload = env.get('SOSECURITY_WEBAUTHN_AUTOLOAD')
                    if not autoload or not Path(autoload).is_file():
                        raise RuntimeError('SOSECURITY_WEBAUTHN_AUTOLOAD must name the local Composer consumer autoload.php')
                    reset = sql('DROP TABLE IF EXISTS sosecurity_test.sosecurity_webauthn_credential; DROP TABLE IF EXISTS sosecurity_test.sosecurity_webauthn_user;')
                    if reset.returncode: raise RuntimeError('Cannot reset private WebAuthn test tables')
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'integrations/webauthn/tests/repository.php'), autoload, 'mysql'], env=env, check=True)
                    continue
                if quarantine_clam:
                    env['SOSECURITY_TEST_QUARANTINE_BACKEND'] = 'mysql'
                    env['SOSECURITY_REQUIRE_CLAMAV'] = '1'
                    subprocess.run(['python3', str(root / 'tests/upload_clamav_real.py'), runtime], env=env, check=True)
                    continue
                if quarantine:
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/upload-quarantine.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/upload-quarantine-backend-factory.php'), 'mysql'], env=env, check=True)
                    env['SOSECURITY_TEST_QUARANTINE_BACKEND'] = 'mysql'
                    subprocess.run(['python3', str(root / 'tests/upload_quarantine.py'), runtime], env=env, check=True)
                    continue
                if snapshots:
                    for name in ['sql','capture','capture-commit','composite-view','example','slot-pages','slot-page-bounds','slot-page-bytes','slot-page-race','slot-page-filter']:
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/state-snapshot'/(name+'.php')),'mysql'],env=env,check=True)
                    continue
                if accounts_only:
                    account_suites(runtime, env)
                    continue
                if sql_dependencies:
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/sql-schema-dependencies.php'), 'mysql'], env=env, check=True)
                    continue
                if account_factors:
                    for backend in ['file-store','mysql-store']:
                        subprocess.run(['python3',str(root/'tests/account_factor.py'),runtime,'mysql',backend],env=env,check=True)
                    continue
                if factor_notices:
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/operations-notices.php'),'mysql','file-store'],env=env,check=True)
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/migration-notices.php'),'mysql','file-store'],env=env,check=True)
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/revocation-notices.php'),'mysql','file-store'],env=env,check=True)
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/recovery-notices.php'),'mysql','file-store'],env=env,check=True)
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/recovery-terminal-notices.php'),'mysql','file-store'],env=env,check=True)
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/restoration-notices.php'),'mysql','file-store'],env=env,check=True)
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/restoration-cleanup-notices.php'),'mysql','file-store'],env=env,check=True)
                    continue
                if remaining_factor_notices:
                    for name in ['enrollment-notices','resolution-notices']:
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor'/(name+'.php')),'mysql','file-store'],env=env,check=True)
                    continue
                if notice_queue_rotation:
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/notice-queue-rotation.php'),'mysql','file-store'],env=env,check=True)
                    continue
                if restoration_cleanup_notices:
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/restoration-cleanup-notices.php'),'mysql','file-store'],env=env,check=True)
                    continue
                if recovery_notices:
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/recovery-notices.php'),'mysql','file-store'],env=env,check=True)
                    continue
                if recovery_terminal_notices:
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/recovery-terminal-notices.php'),'mysql','file-store'],env=env,check=True)
                    continue
                if migration_notices:
                    subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/account-factor/migration-notices.php'),'mysql','file-store'],env=env,check=True)
                    continue
                if outbox_reconciliation:
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/outbox-reconciliation.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/outbox-reconciliation-concurrency.php'), 'mysql'], env=env, check=True)
                    continue
                if outbox_concurrency:
                    subprocess.run([runtime, str(root / 'tests/outbox-concurrency.php'), 'mysql'], env=env, check=True)
                    continue
                if outbox:
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/sql-schema-dependencies.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/outbox.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/outbox-safety.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/outbox-reconciliation.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/outbox-reconciliation-concurrency.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/outbox-concurrency.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/outbox-input-bounds.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root / 'tests/outbox-hard-limit.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/outbox-index-budget.php'), 'mysql'], env=env, check=True)
                    continue
                if sql_enlistment:
                    subprocess.run([runtime, str(root / 'tests/sql-enlistment.php'), 'mysql'], env=env, check=True)
                    continue
                if idempotency:
                    subprocess.run([runtime, str(root / 'tests/idempotency.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/idempotency-safety.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/idempotency-concurrency.php'), 'mysql'], env=env, check=True)
                    continue
                if webhook_processing:
                    subprocess.run([runtime, str(root / 'tests/webhook-processing.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/webhook-processing-concurrency.php'), 'mysql'], env=env, check=True)
                    ownership(runtime, env, ['processing','inbox','store','prune','install'])
                    continue
                if webhook_inbox:
                    subprocess.run([runtime, str(root / 'tests/webhook-inbox.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/webhook-inbox-concurrency.php'), 'mysql'], env=env, check=True)
                    ownership(runtime, env, ['inbox'])
                    continue
                account_suites(runtime, env)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/sql-schema-dependencies.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/outbox.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/outbox-safety.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/outbox-reconciliation.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/outbox-reconciliation-concurrency.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/outbox-concurrency.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/outbox-input-bounds.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=32M', str(root / 'tests/outbox-hard-limit.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/sql-enlistment.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/idempotency.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/idempotency-safety.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/idempotency-concurrency.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/mysql.php')], env=env, check=True)
                subprocess.run(['python3', str(root/'tests/audit_metrics_process.py'), runtime, 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-metrics-fault.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-recent-events.php'), 'mysql'], env=env, check=True)
                subprocess.run(['python3', str(root/'tests/audit_recent_process.py'), runtime, 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-alert-outbox.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-alert-retained.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-alert-worker.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/api.php')], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/lease-sql.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/operation-sql.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/webhook-inbox.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/webhook-inbox-concurrency.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/webhook-processing.php'), 'mysql'], env=env, check=True)
                subprocess.run([runtime, str(root / 'tests/webhook-processing-concurrency.php'), 'mysql'], env=env, check=True)
                ownership(runtime, env, ['processing','inbox','store','prune','install'])
                subprocess.run([runtime, str(root / 'tests/concurrency.php')], env=env, check=True)
    finally:
        if server.poll() is None:
            sql('SHUTDOWN')
            try: server.wait(timeout=10)
            except subprocess.TimeoutExpired: server.terminate(); server.wait(timeout=5)
        log.close()
