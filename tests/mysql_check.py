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
sql_dependencies = len(sys.argv)>1 and sys.argv[1] in ['--webhook-pending-authority','--webhook-pending-read','--webhook-processing-budget','--webhook-processing-read-cleanup','--webhook-schema-cleanup','--webhook-metadata-budget','--webhook-receive-cleanup','--audit-sql-cleanup','--idempotency-observation-cleanup','--queued-page-cleanup','--queued-read-cleanup','--outbox-sent-purge','--queued-write-cleanup','--ledger-write-cleanup','--ledger-read-values','--ledger-read-cleanup','--private-schema-cleanup','--snapshot-locked-schema','--snapshot-stream-cleanup','--fixed-variable-format','--snapshot-text-pool','--snapshot-resolution-locks','--snapshot-resolution','--sql-snapshot-context','--sql-database-bytes','--ledger-context-pool','--ledger-final-structure','--sql-policy-drift','--sql-wait-native-delay','--ledger-durable-context','--sql-read-wait-restore','--sql-read-in-readonly','--ledger-partial-revokes-cleanup','--ledger-shared-permissions','--ledger-shared-visibility','--sql-read-wait-pair','--sql-cleanup-regression','--sql-caught-cleanup','--ledger-context-cleanup-protected','--ledger-context-cleanup','--credential-cold-capture','--mysql-store-constructor','--webhook-lock-policy','--mysql-store-lock-timeout','--sql-metadata-wait','--sql-operation-budget','--sql-fixed-context','--sql-owned-entry','--sql-guard-cursor','--ledger-context-batch','--ledger-statements','--ledger-root-batch','--sql-lock-limit','--file-snapshot-context','--sql-lock-timeout','--sql-unit-precheck','--sql-witness-batch','--sql-witness-transport','--sql-durable-statements','--factor-initial-read','--locked-schema','--sql-schema-mdl','--sql-resolution-budget','--schema-clock-context','--captured-session-expiry','--audit-window-archive','--current-worker-context','--current-worker-read','--mysql-resolved-table','--remember-risk-boundary','--sql-schema-pair','--sql-context','--sql-schema-unexpected-unique','--sql-metadata-statements','--sql-schema-visibility','--mysql-trigger-global-race','--mysql-store-visibility','--webhook-schema-visibility','--webhook-schema','--configuration-presets','--mysql-store-triggers','--session-current-authority','--mysql-store-schema-drift','--sql-dependencies','--sql-schema-queries','--sql-schema-index-batch','--sql-foreign-plan','--mysql-store-index','--mysql-store-regression','--mysql-store-extra-index','--mysql-store-metadata','--mysql-store-errors','--ledger-read-capture','--ledger-checkpoint-read','--factor-checkpoint-read']
accounts_only = len(sys.argv)>1 and sys.argv[1]=='--accounts'
webhook_state_factory = len(sys.argv)>1 and sys.argv[1]=='--webhook-state-factory'
webhook_state_race = len(sys.argv)>1 and sys.argv[1]=='--webhook-state-race'
api_key_time = len(sys.argv)>1 and sys.argv[1]=='--api-key-time'
api_key_state = len(sys.argv)>1 and sys.argv[1]=='--api-key-state'
native_maintenance = len(sys.argv)>1 and sys.argv[1] in ['--native-address-captured','--native-captured-permissions','--outbox-known-current','--native-maintenance','--native-maintenance-factory','--expired-request-maintenance','--permission-clock','--native-proofs','--factor-notice-maintenance','--outbox-rotation','--outbox-initial','--outbox-initial-admission','--outbox-initial-prewrite','--outbox-initial-defaults','--outbox-current','--outbox-ack','--outbox-reject','--dispatch-budget-state','--native-first-dispatch','--native-rejected-dispatch','--native-address-proofs','--native-address-actions','--native-leases','--native-leases-completion','--proof-return','--quarantine-source','--native-quarantine','--native-quarantine-factory','--idempotency-factory-boundary','--native-idempotency-maintenance','--native-idempotency-request','--idempotency-final-reentry','--native-audit-source','--native-audit-write','--native-audit-delegation','--native-audit-defaults','--native-audit-clock','--native-audit-deadline','--native-credential-pair','--native-factor-locations','--native-audit-profile','--native-audit-completed-budget','--native-custom-policy','--native-custom-policy-faults','--native-business-return','--native-bearer-return','--native-business-policy','--native-operation-return','--native-hmac-return','--native-link-return','--native-remember-return','--native-auth-return','--native-reset-proof-return']
api_key_state_race = len(sys.argv)>1 and sys.argv[1]=='--api-key-state-race'
webhook_state_source = len(sys.argv)>1 and sys.argv[1]=='--webhook-state-source'
fresh_authentication = len(sys.argv)>1 and sys.argv[1]=='--fresh-authentication'
ordinary_ledger = len(sys.argv)>1 and sys.argv[1]=='--ordinary-ledger-maintenance'
ordinary_maintenance = len(sys.argv)>1 and sys.argv[1] in ['--ordinary-account-maintenance','--ordinary-ledger-maintenance']
outbox = len(sys.argv)>1 and sys.argv[1]=='--outbox'
quarantine = len(sys.argv)>1 and sys.argv[1]=='--quarantine'
quarantine_clam = len(sys.argv)>1 and sys.argv[1]=='--quarantine-clam'
outbox_concurrency = len(sys.argv)>1 and sys.argv[1]=='--outbox-concurrency'
outbox_reconciliation = len(sys.argv)>1 and sys.argv[1]=='--outbox-reconciliation'
account_factors = len(sys.argv)>1 and sys.argv[1]=='--account-factors'
state_codecs = len(sys.argv)>1 and sys.argv[1]=='--state-codecs'
state_boundary = len(sys.argv)>1 and sys.argv[1]=='--state-boundary'
state_fence_source = len(sys.argv)>1 and sys.argv[1]=='--state-fence-source'
state_entry = len(sys.argv)>1 and sys.argv[1]=='--state-entry'
state_stale = len(sys.argv)>1 and sys.argv[1]=='--state-stale'
state_account_resolution = len(sys.argv)>1 and sys.argv[1]=='--state-account-resolution'
state_recovery_audit = len(sys.argv)>1 and sys.argv[1]=='--state-recovery-audit'
state_api_retirement = len(sys.argv)>1 and sys.argv[1]=='--state-api-retirement'
state_api_crash = len(sys.argv)>1 and sys.argv[1]=='--state-api-crash'
state_managed_api = len(sys.argv)>1 and sys.argv[1]=='--state-managed-api'
state_admission_capacity = len(sys.argv)>1 and sys.argv[1]=='--state-admission-capacity'
state_native_hmac = len(sys.argv)>1 and sys.argv[1]=='--state-native-hmac'
state_native_reset = len(sys.argv)>1 and sys.argv[1]=='--state-native-reset'
state_native_links = len(sys.argv)>1 and sys.argv[1]=='--state-native-links'
state_native_grants = len(sys.argv)>1 and sys.argv[1] in ['--state-native-grants-basic','--state-native-grants-outcomes','--state-native-grants-factory']
state_business_crash = len(sys.argv)>1 and sys.argv[1]=='--state-business-crash'
state_business_integration = len(sys.argv)>1 and sys.argv[1]=='--state-business-integration'
state_api_business = len(sys.argv)>1 and sys.argv[1]=='--state-api-business'
state_api_intent = len(sys.argv)>1 and sys.argv[1]=='--state-api-intent'
state_api_intent_crash = len(sys.argv)>1 and sys.argv[1]=='--state-api-intent-crash'
state_http = len(sys.argv)>1 and sys.argv[1] in ['--state-http','--state-http-tls','--state-http-business']
state_api_native = len(sys.argv)>1 and sys.argv[1] in ['--state-api-native','--state-api-native-workflows','--state-api-native-refusals']
state_managed_api_crash = len(sys.argv)>1 and sys.argv[1]=='--state-managed-api-crash'
state_session_failed = len(sys.argv)>1 and sys.argv[1]=='--state-session-failed'
state_session_retirement = len(sys.argv)>1 and sys.argv[1]=='--state-session-retirement'
state_session_crash = len(sys.argv)>1 and sys.argv[1]=='--state-session-crash'
state_crash = len(sys.argv)>1 and sys.argv[1]=='--state-crash'
state_proof_retirement = len(sys.argv)>1 and sys.argv[1]=='--state-proof-retirement'
state_installation_retirement = len(sys.argv)>1 and sys.argv[1]=='--state-installation-retirement'
state_installation = len(sys.argv)>1 and sys.argv[1]=='--state-installation'
state_credentials = len(sys.argv)>1 and sys.argv[1]=='--state-credentials'
state_budget = len(sys.argv)>1 and sys.argv[1]=='--state-budget'
state_requests = len(sys.argv)>1 and sys.argv[1]=='--state-requests'
state_lifecycle = len(sys.argv)>1 and sys.argv[1]=='--state-lifecycle'
state_factory = len(sys.argv)>1 and sys.argv[1]=='--state-factory'
factor_notices = len(sys.argv)>1 and sys.argv[1]=='--factor-notices'
restoration_cleanup_notices = len(sys.argv)>1 and sys.argv[1]=='--restoration-cleanup-notices'
recovery_notices = len(sys.argv)>1 and sys.argv[1]=='--recovery-notices'
recovery_terminal_notices = len(sys.argv)>1 and sys.argv[1]=='--recovery-terminal-notices'
migration_notices = len(sys.argv)>1 and sys.argv[1]=='--migration-notices'
remaining_factor_notices = len(sys.argv)>1 and sys.argv[1]=='--remaining-factor-notices'
notice_queue_rotation = len(sys.argv)>1 and sys.argv[1]=='--notice-queue-rotation'
snapshots = len(sys.argv)>1 and sys.argv[1]=='--snapshots'
webauthn = len(sys.argv)>1 and sys.argv[1] in ['--webauthn','--webauthn-devices']
oidc_process = len(sys.argv)>1 and sys.argv[1]=='--oidc-process'
audit_metrics = len(sys.argv)>1 and sys.argv[1]=='--audit-metrics'
audit_alert = len(sys.argv)>1 and sys.argv[1]=='--audit-alert'
audit_sql = len(sys.argv)>1 and sys.argv[1]=='--audit-sql'
snapshot_schema_queries = len(sys.argv)>1 and sys.argv[1] in ['--snapshot-schema-queries','--snapshot-schema-baseline','--snapshot-schema-batch','--snapshot-schema-batch-baseline']
authorization_audit = len(sys.argv)>1 and sys.argv[1]=='--authorization-audit-policy'
runtimes = sys.argv[2:] if native_maintenance or api_key_state_race or api_key_state or api_key_time or webhook_state_race or webhook_state_factory or webhook_state_source or fresh_authentication or ordinary_maintenance or accounts_only or matrix or webhook_inbox or webhook_processing or idempotency or sql_enlistment or sql_dependencies or outbox or quarantine or quarantine_clam or outbox_concurrency or outbox_reconciliation or account_factors or state_codecs or state_boundary or state_fence_source or state_entry or state_factory or state_lifecycle or state_requests or state_budget or state_stale or state_account_resolution or state_recovery_audit or state_api_retirement or state_api_crash or state_managed_api or state_api_native or state_http or state_admission_capacity or state_native_hmac or state_native_reset or state_native_links or state_native_grants or state_business_crash or state_business_integration or state_api_business or state_api_intent or state_api_intent_crash or state_managed_api_crash or state_session_failed or state_session_retirement or state_session_crash or state_crash or state_installation or state_installation_retirement or state_proof_retirement or state_credentials or factor_notices or restoration_cleanup_notices or recovery_notices or recovery_terminal_notices or migration_notices or remaining_factor_notices or notice_queue_rotation or snapshots or webauthn or oidc_process or audit_metrics or audit_alert or audit_sql or authorization_audit or snapshot_schema_queries else sys.argv[1:]
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
    if audit_sql or snapshots or quarantine or quarantine_clam or state_codecs or state_boundary or state_fence_source or state_entry or state_factory or state_lifecycle or state_requests or state_budget or state_stale or state_account_resolution or state_recovery_audit or state_api_retirement or state_api_crash or state_managed_api or state_api_native or state_http or state_admission_capacity or state_native_hmac or state_native_reset or state_native_links or state_native_grants or state_business_crash or state_business_integration or state_api_business or state_api_intent or state_api_intent_crash or state_managed_api_crash or state_session_failed or state_session_retirement or state_session_crash or state_crash or state_installation or state_installation_retirement or state_proof_retirement or state_credentials: print('OWNED_INSTANCE '+directory,flush=True)
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
        if (sql_dependencies and sys.argv[1] in ['--locked-schema','--sql-schema-pair','--sql-metadata-statements','--sql-schema-visibility','--mysql-trigger-global-race','--mysql-store-visibility','--sql-foreign-plan','--webhook-schema','--webhook-schema-visibility']) or (len(sys.argv)>1 and not sys.argv[1].startswith('--')):
            probe=sql("CREATE DATABASE sosecurity_fk_other; CREATE USER 'sosecurity_reader'@'localhost' IDENTIFIED WITH mysql_native_password BY 'integration-read-only'; GRANT SELECT ON sosecurity_test.* TO 'sosecurity_reader'@'localhost'; GRANT SELECT ON sosecurity_fk_other.* TO 'sosecurity_reader'@'localhost'; GRANT ALL ON sosecurity_fk_other.* TO 'sosecurity_test'@'localhost';")
            if probe.returncode: raise RuntimeError('Owned foreign dependency probe setup failed')
        if state_boundary or state_fence_source or state_stale or state_account_resolution or state_recovery_audit or state_api_retirement or state_api_crash or state_managed_api or state_api_native or state_http or state_admission_capacity or state_native_hmac or state_native_reset or state_native_links or state_native_grants or state_business_crash or state_business_integration or state_api_business or state_api_intent or state_api_intent_crash or state_managed_api_crash or state_session_failed or state_session_retirement or state_session_crash or state_crash or state_installation or state_installation_retirement or state_proof_retirement or state_credentials or matrix:
            # Fixed destructive recovery refuses filtered dependency metadata. This permission is
            # granted only on the controller-owned disposable server, never on a business server.
            if sql("GRANT TRIGGER ON *.* TO 'sosecurity_test'@'localhost'").returncode:
                raise RuntimeError('Owned recovery metadata visibility setup failed')
        if sql_dependencies and sys.argv[1]=='--schema-clock-context':
            if sql("CREATE USER 'sosecurity_schema_clock'@'localhost' IDENTIFIED WITH mysql_native_password BY 'integration-only'; GRANT ALL ON *.* TO 'sosecurity_schema_clock'@'localhost';").returncode:
                raise RuntimeError('Owned schema clock account setup failed')
        env = os.environ.copy()
        if oidc_process or ordinary_maintenance or native_maintenance:
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
                if snapshot_schema_queries:
                    if sys.argv[1] in ['--snapshot-schema-batch','--snapshot-schema-batch-baseline']:
                        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/state-snapshot/schema-batch.php'), 'mysql', 'observe' if sys.argv[1]=='--snapshot-schema-batch-baseline' else 'check'], env=env, check=True)
                        if sys.argv[1]=='--snapshot-schema-batch':
                            for test in ['schema-union','schema-batch-bounds','schema-roundtrips','sql','capture','capture-commit','composite-view']:
                                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/('tests/state-snapshot/'+test+'.php')), 'mysql'], env=env, check=True)
                        continue
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/state-snapshot/schema-roundtrips.php'), 'mysql', 'observe' if sys.argv[1]=='--snapshot-schema-baseline' else 'check'], env=env, check=True)
                    if sys.argv[1]=='--snapshot-schema-queries':
                        for test in ['sql','capture','capture-commit','composite-view']:
                            subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/('tests/state-snapshot/'+test+'.php')), 'mysql'], env=env, check=True)
                    continue
                if authorization_audit:
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/authorization-audit-policy-sql.php'), 'mysql'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-leases-completion':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'leases', 'normal'], env=env, check=True)
                    for mode in ['forward','backward','authority']:
                        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/state-boundary/native-lease-final-time.php'), mode, 'mysql'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-leases':
                    for mode in ['normal','expiry','late','prewrite','guard-error','clock-error','corrupt']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'leases', mode], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/lease-sql.php'), 'mysql'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-address-captured':
                    outcomes=[]
                    for mode in ['normal','role','deny','changed','effect-reentry','return-deny','effect-fault','request-late-before','request-late-commit','request-late-complete','complete-late-before','complete-late-commit','complete-late-complete','request-final-guard','complete-final-guard','request-final-fault','complete-final-expiry','proposal-final-guard','completion-proposal-final-guard','request-flow-final-expiry']:
                        outcomes.append(subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/state-boundary/native-maintenance.php'),'mysql','factory','address_actions','captured-'+mode],env=env).returncode)
                    if any(outcomes):raise RuntimeError('Captured address checks failed: '+repr(outcomes))
                    continue
                if native_maintenance and sys.argv[1]=='--native-address-actions':
                    for mode in ['normal','expiry','mismatch','request-late','complete-late']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'address_actions', mode], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/address-change.php'), 'mysql'], env=env, check=True)
                    cleanup=sql('USE sosecurity_test; DROP TABLE account_example,sosecurity_account_records,sosecurity_account_roots,sosecurity_outbox_records,sosecurity_outbox_roots')
                    if cleanup.returncode: raise RuntimeError('Owned address change table cleanup failed')
                    continue
                if native_maintenance and sys.argv[1]=='--native-address-proofs':
                    for mode in ['normal','subject-budget','final-budget','late','budget-effects','guard-error']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'address_proofs', mode], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/address-change.php'), 'mysql'], env=env, check=True)
                    cleanup=sql('USE sosecurity_test; DROP TABLE account_example,sosecurity_account_records,sosecurity_account_roots,sosecurity_outbox_records,sosecurity_outbox_roots')
                    if cleanup.returncode: raise RuntimeError('Owned address change table cleanup failed')
                    continue
                if native_maintenance and sys.argv[1]=='--native-rejected-dispatch':
                    for mode in ['retry-normal','retry-limit','retry-permanent','retry-expiry','retry-revoke-gate','retry-revoke-after']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'native_dispatch', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-first-dispatch':
                    for mode in ['normal','rejected','revoke-before','revoke-after','revoke-gate','unknown','budget']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'native_dispatch', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--dispatch-budget-state':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'dispatch_budgets'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/account-mail-factory.php'), 'mysql'], env=env, check=True)
                    cleanup=sql('USE sosecurity_test; DROP TABLE account_example,sosecurity_account_records,sosecurity_account_roots,sosecurity_outbox_records,sosecurity_outbox_roots')
                    if cleanup.returncode: raise RuntimeError('Owned mail factory table cleanup failed')
                    continue
                if native_maintenance and sys.argv[1]=='--outbox-known-current':
                    outcomes=[]
                    for mode in ['defaults','ack','reject']:
                        outcomes.append(subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/state-boundary/native-maintenance.php'),'mysql','factory','outbox_initial',mode],env=env).returncode)
                    if any(outcomes): raise RuntimeError('Known-result outbox checks failed: '+str(outcomes))
                    continue
                if native_maintenance and sys.argv[1]=='--outbox-reject':
                    for mode in ['reject','reject-expiry','reject-late-role','reject-late-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_initial', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--outbox-ack':
                    for mode in ['ack','ack-expiry','ack-late-role','ack-late-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_initial', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--outbox-current':
                    for mode in ['current','current-expiry','current-late-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_initial', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--outbox-initial-defaults':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_initial', 'defaults'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--outbox-initial-prewrite':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/operation-deadline.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_initial', 'prewrite'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1] in ['--outbox-initial','--outbox-initial-admission']:
                    if sys.argv[1]=='--outbox-initial':
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/outbox-initial-claim.php'), 'mysql'], env=env, check=True)
                    for mode in (['normal','expiry','budget'] if sys.argv[1]=='--outbox-initial' else ['expiry','budget']):
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_initial', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--outbox-rotation':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/outbox-rotation.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_rotation'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--factor-notice-maintenance':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/factor-notice-completion.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'factor_notices'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-remember-return':
                    for mode in ['issue-normal','issue-guard','resume-normal','resume-risk-deny','resume-risk-invalid-reason','resume-risk-invalid-action']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'remember-return-'+mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-auth-return':
                    for mode in ['password-normal','password-guard','second_factor-normal','second_factor-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'auth-return-'+mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-reset-proof-return':
                    for mode in ['issue-normal','consume-guard','execute-normal','execute-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'reset-proof-return-'+mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-link-return':
                    for mode in ['issue-normal','verify-guard','execute-normal','execute-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'link-return-'+mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-captured-permissions':
                    outcomes=[]
                    for feature in ['links','grants']:
                        for mode in ['normal','deny','fields','fault','selectors-fault','reentry','effect-deny','return-deny']+(['changed'] if feature=='grants' else []):
                            outcomes.append(subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/state-boundary/native-maintenance.php'),'mysql','factory','audit_delegation','captured-permission-'+feature+'-'+mode],env=env).returncode)
                    if any(outcomes):raise RuntimeError('Captured native permissions failed: '+repr(outcomes))
                    continue
                if native_maintenance and sys.argv[1]=='--native-hmac-return':
                    for mode in ['verify-normal','verify-guard','execute-normal','execute-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'hmac-return-'+mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-operation-return':
                    for mode in ['begin-normal','consume-guard','execute-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'operation-return-'+mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-business-policy':
                    for mode in ['normal','denied','before-fault','return-denied']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'policy-business-'+mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-bearer-return':
                    for mode in ['bearer-auth-normal','bearer-header-narrow','bearer-header-expiry','business-normal']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-business-return':
                    for mode in ['business-normal','business-guard','business-scope','business-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-custom-policy-faults':
                    for mode in ['custom-before-fault','custom-return-fault']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-custom-policy':
                    for mode in ['custom-audit','custom-data-denied','custom-selector-write','custom-selector-fault','custom-selector-invalid','custom-before-fault','custom-return-fault']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-audit-completed-budget':
                    for mode in ['post-audit-delay','post-audit-denial','post-audit-timeout','audit-admission-timeout']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-audit-profile':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', 'profile-defaults'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-factor-locations':
                    subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/state-boundary/native-maintenance.php'),'mysql','factory','audit_delegation','read-factor-locations'],env=env,check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-credential-pair':
                    for mode in ['read-pair','normal','return-denial','return-expiry','return-scope','return-clock']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-audit-deadline':
                    for mode in ['sink-budget','budget','normal']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_write', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1] in ['--native-audit-delegation','--native-audit-defaults','--native-audit-clock','--native-audit-deadline','--native-credential-pair','--native-factor-locations','--native-audit-profile','--native-audit-completed-budget','--native-custom-policy','--native-custom-policy-faults','--native-business-return','--native-bearer-return','--native-business-policy','--native-operation-return','--native-hmac-return','--native-link-return','--native-reset-proof-return']:
                    modes=['return-clock'] if sys.argv[1]=='--native-audit-clock' else ['defaults'] if sys.argv[1]=='--native-audit-defaults' else ['normal','return-denial','return-expiry','return-scope','return-fault']
                    for mode in modes:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_delegation', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-audit-write':
                    subprocess.run([runtime, str(root/'tests/audit-sql.php'), 'mysql'], env=env, check=True)
                    if sql('DROP TABLE sosecurity_test.sosecurity_audit_records, sosecurity_test.sosecurity_audit_roots').returncode:
                        raise RuntimeError('Owned ordinary audit table cleanup failed')
                    for mode in ['normal','physical','changed','budget','clock']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'audit_write', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-audit-source':
                    subprocess.run([runtime, str(root/'tests/audit-sql.php'), 'mysql'], env=env, check=True)
                    # The ordinary fixture retains its two tables until this owned server closes.
                    # Remove only those just-created test tables before the native fixture creates them.
                    if sql('DROP TABLE sosecurity_test.sosecurity_audit_records, sosecurity_test.sosecurity_audit_roots').returncode:
                        raise RuntimeError('Owned ordinary audit table cleanup failed')
                    for mode in ['audit_source','audit_missing']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--idempotency-final-reentry':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'idempotency', 'final-reentry'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-idempotency-request':
                    for mode in ['normal','defaults','rollback','final-denial','final-expiry','lookup-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'idempotency_request', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-idempotency-maintenance':
                    for mode in ['normal','defaults','backward','final-denial','final-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'idempotency', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--idempotency-factory-boundary':
                    for method in ['idempotency','outbox']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'idempotency_factory', method], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'outbox_rotation'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-quarantine-factory':
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'quarantine'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-quarantine':
                    for mode in ['normal','tamper','late-denial','final-denial','final-expiry']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-quarantine.php'), 'mysql', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--quarantine-source':
                    for mode in ['normal','tamper']:
                        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/state-boundary/quarantine-source.php'), 'mysql', mode], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--proof-return':
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/state-boundary/proof-return.php'), 'all', 'all', 'mysql'], env=env, check=True)
                    for mode in ['normal','restore','late','expiry-admission','expiry-late']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/proof-state.php'), 'mysql', mode], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'proofs'], env=env, check=True)
                    continue
                if native_maintenance and sys.argv[1]=='--native-proofs':
                    for mode in ['normal','restore','late','expiry-admission','expiry-late']:
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/proof-state.php'), 'mysql', mode], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql', 'factory', 'proofs'], env=env, check=True)
                    continue
                if native_maintenance:
                    for variant in ([['factory','clock'],['factory','mapping']] if sys.argv[1]=='--permission-clock' else ([['factory','recovery'],['factory','mailbox_recovery']] if sys.argv[1]=='--expired-request-maintenance' else ([['factory'], ['factory','mapping']] if sys.argv[1]=='--native-maintenance-factory' else [[]]))):
                        subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/native-maintenance.php'), 'mysql']+variant, env=env, check=True)
                    continue
                if api_key_state_race:
                    subprocess.run([runtime, str(root/"tests/api-key-state.php"), "mysql", "race"], env=env, check=True)
                    continue
                if api_key_state:
                    for mode in ["normal", "epoch", "late-deny", "late-expiry", "budget"]:
                        subprocess.run([runtime, str(root/"tests/api-key-state.php"), "mysql", mode], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/state-boundary/fresh-webhook-shared.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/api-key-time.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/api.php")], env=env, check=True)
                    continue
                if api_key_time:
                    subprocess.run([runtime, str(root/"tests/api-key-time.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/api-epoch.php")], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/api.php")], env=env, check=True)
                    continue
                if webhook_state_race:
                    subprocess.run([runtime, str(root/"tests/webhook-state-factory.php"), "mysql", "processing-race"], env=env, check=True)
                    continue
                if webhook_state_factory:
                    for mode in ["processing-failure", "processing-late-revoke"]:
                        subprocess.run([runtime, str(root/"tests/webhook-state-factory.php"), "mysql", mode], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/webhook-processing.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/webhook-state-factory.php"), "mysql", "completion-revoke"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/webhook-completion-authority.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/webhook-state-factory.php"), "mysql", "mapping-change"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/webhook-request-authority.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/webhook-inbox.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, "-d", "memory_limit=16M", str(root/"tests/webhook-state-factory.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, "-d", "memory_limit=32M", str(root/"tests/state-boundary/fresh-webhook-shared.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root/"tests/webhook-processing-factory.php"), "mysql"], env=env, check=True)
                    continue
                if webhook_state_source:
                    subprocess.run([runtime, "-d", "memory_limit=16M", str(root/"tests/webhook-state-source.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, "-d", "memory_limit=8M", str(root/"tests/state-snapshot/composite-view.php"), "mysql"], env=env, check=True)
                    continue
                if fresh_authentication:
                    subprocess.run([runtime, '-d', 'memory_limit=32M', str(root/'tests/state-boundary/fresh-authentication.php'), 'mysql'], env=env, check=True)
                    continue
                if ordinary_maintenance:
                    if subprocess.run([runtime, '-r', 'exit(extension_loaded("sodium") ? 0 : 1);'], env=env).returncode:
                        raise RuntimeError('Ordinary account maintenance requires real ext-sodium')
                    for test in (['registration-ledger-maintenance'] if ordinary_ledger else ['registration-capacity', 'registration-maintenance', 'address-change-maintenance', 'maintenance-completion-authority']):
                        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests'/(test+'.php')), 'mysql'], env=env, check=True)
                    continue
                if oidc_process:
                    autoload = env.get('SOSECURITY_OIDC_AUTOLOAD')
                    if not autoload or not Path(autoload).is_file():
                        raise RuntimeError('SOSECURITY_OIDC_AUTOLOAD must name the local Composer consumer autoload.php')
                    if not oidc_installed:
                        install = 'require getenv("SOSECURITY_TEST_ROOT")."/vendor/autoload.php"; $pdo=new PDO("mysql:unix_socket=".getenv("SOSECURITY_TEST_MYSQL_SOCKET").";dbname=sosecurity_test;charset=utf8mb4","sosecurity_test","integration-only",[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]); SoSecurity\\Storage\\MySqlStore::install($pdo);'
                        subprocess.run([runtime, '-r', install], env=env, check=True)
                        oidc_installed = True
                    subprocess.run([sys.executable, str(root / 'integrations/oidc/tests/process_race.py'), autoload, runtime], env=env, check=True)
                    subprocess.run([runtime, str(root / 'integrations/oidc/tests/sessions.php'), autoload, 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'integrations/oidc/tests/batch-unlink.php'), autoload, 'mysql'], env=env, check=True)
                    if subprocess.run([runtime, '-r', 'exit(extension_loaded("sodium") ? 0 : 1);'], env=env).returncode == 0:
                        subprocess.run([runtime, str(root / 'integrations/oidc/tests/mfa-login.php'), autoload, 'mysql'], env=env, check=True)
                        subprocess.run([sys.executable, str(root / 'integrations/oidc/tests/mfa_process.py'), autoload, runtime], env=env, check=True)
                    else:
                        print('NOT RUN encrypted OIDC MFA MySQL: ext-sodium required', flush=True)
                        if env.get('SOSECURITY_REQUIRE_CRYPTO') == '1': raise RuntimeError('Required OIDC MFA test dependency unavailable')
                    continue
                if audit_metrics:
                    install = 'require getenv("SOSECURITY_TEST_ROOT")."/vendor/autoload.php"; $pdo=new PDO("mysql:unix_socket=".getenv("SOSECURITY_TEST_MYSQL_SOCKET").";dbname=sosecurity_test;charset=utf8mb4","sosecurity_test","integration-only",[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]); SoSecurity\\Storage\\MySqlStore::install($pdo);'
                    subprocess.run([runtime, '-r', install], env=env, check=True)
                    subprocess.run(['python3', str(root/'tests/audit_metrics_process.py'), runtime, 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-metrics-fault.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-recent-events.php'), 'mysql'], env=env, check=True)
                    subprocess.run(['python3', str(root/'tests/audit_recent_process.py'), runtime, 'mysql'], env=env, check=True)
                    continue
                if audit_sql:
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-sql.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-sql-history.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-sql-fault.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/audit-sql-pipeline.php'), 'mysql'], env=env, check=True)
                    subprocess.run([sys.executable, str(root/'tests/audit_sql_process.py'), runtime, 'mysql'], env=env, check=True)
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
                    if sys.argv[1]=='--webauthn-devices':
                        for mode in ['permission','before','current','return','notice','clock-before','clock-return']:
                            subprocess.run([runtime,'-d','memory_limit=8M',str(root/'integrations/webauthn/tests/device-boundary.php'),autoload,mode,'mysql'],env=env,check=True)
                        continue
                    reset = sql('DROP TABLE IF EXISTS sosecurity_test.sosecurity_webauthn_credential; DROP TABLE IF EXISTS sosecurity_test.sosecurity_webauthn_user;')
                    if reset.returncode: raise RuntimeError('Cannot reset private WebAuthn test tables')
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'integrations/webauthn/tests/repository.php'), autoload, 'mysql'], env=env, check=True)
                    for mode in ['permission','before','current','return','notice','clock-before','clock-return']:
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'integrations/webauthn/tests/device-boundary.php'),autoload,mode,'mysql'],env=env,check=True)
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
                    if sys.argv[1]=='--sql-wait-native-delay':
                        subprocess.run(['python3',str(root/'tests/sql_wait_native_delay.py'),runtime],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-durable-context':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-durable-context.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-read-wait-restore':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-read-wait-restore.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-read-wait-restore-failure.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-read-in-readonly':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-read-in-readonly.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-read-in-owner.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-partial-revokes-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-partial-revokes-cleanup.php')],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-partial-revokes-cleanup.php'),'protected'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-shared-permissions':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-shared-permissions.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-shared-visibility':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-shared-visibility.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-read-wait-pair':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-read-wait-pair.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--fixed-variable-format':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/fixed-variable-format.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-pending-authority':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/webhook-pending-authority.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-pending-read':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/webhook-pending-read.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-processing-budget':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/webhook-processing-budget.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-processing-read-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/webhook-processing-read-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-schema-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/webhook-schema-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-metadata-budget':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/webhook-metadata-budget.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-receive-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/webhook-receive-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--audit-sql-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/audit-sql-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--idempotency-observation-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/idempotency-observation-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--queued-page-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/queued-page-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    elif sys.argv[1]=='--queued-read-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/queued-read-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--outbox-sent-purge':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/outbox-sent-purge.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--queued-write-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/queued-write-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-write-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-write-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-read-values':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-read-values.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-read-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-read-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--private-schema-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/private-schema-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--snapshot-locked-schema':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/snapshot-locked-schema.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--snapshot-stream-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/snapshot-stream-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--snapshot-text-pool':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/snapshot-text-pool.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--snapshot-resolution-locks':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/snapshot-resolution-locks.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--snapshot-resolution':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/snapshot-resolution.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-snapshot-context':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-snapshot-context.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-database-bytes':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-database-bytes.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-context-pool':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-context-pool.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-final-structure':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-final-structure.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-policy-drift':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-policy-drift.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-context-batch':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-context-batch.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-statements':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-projection-text.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-statements.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-root-batch':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-root-batch.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-lock-limit':
                        subprocess.run([runtime,str(root/'tests/sql-lock-limit.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--file-snapshot-context':
                        for name in ['composite-view','staging']:
                            subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/state-snapshot'/(name+'.php')),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-cleanup-regression':
                        cleanup_cases=[('sql-caught-cleanup.php',['mysql']),('sql-read-in-fallback.php',['mysql']),('sql-caught-cleanup-reentrant.php',['mysql']),('ledger-context-cleanup.php',[]),('ledger-context-cleanup.php',['protected'])]
                        cleanup_results=[subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests'/name),*args],env=env).returncode for name,args in cleanup_cases]
                        if any(cleanup_results): raise RuntimeError('Private SQL cleanup checks failed: '+str(cleanup_results))
                        continue
                    if sys.argv[1]=='--sql-caught-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-caught-cleanup.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-context-cleanup-protected':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-context-cleanup.php'),'protected'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-context-cleanup':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-context-cleanup.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--credential-cold-capture':
                        subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/state-boundary/native-maintenance.php'),'mysql','factory','audit_delegation','read-cold'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--mysql-store-constructor':
                        subprocess.run([runtime,str(root/'tests/mysql-store-constructor.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-lock-policy':
                        subprocess.run([runtime,str(root/'tests/webhook-lock-timeout.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,str(root/'tests/webhook-lock-policy.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--mysql-store-lock-timeout':
                        subprocess.run([runtime,str(root/'tests/mysql-store-lock-timeout.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-metadata-wait':
                        subprocess.run([runtime,str(root/'tests/sql-metadata-wait.php')],env=env,check=True)
                        subprocess.run([runtime,str(root/'tests/sql-metadata-timeout-errors.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,str(root/'tests/sql-metadata-policy-failures.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-operation-budget':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-operation-budget.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-fixed-context':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-fixed-context.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-owned-entry':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-owned-entry.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-guard-cursor':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-guard-cursor.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-lock-timeout':
                        subprocess.run([runtime,str(root/'tests/sql-lock-timeout.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,str(root/'tests/sql-lock-timeout-cache.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-unit-precheck':
                        subprocess.run([runtime,str(root/'tests/sql-unit-precheck.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-witness-batch':
                        subprocess.run([runtime,str(root/'tests/sql-witness-batch.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-witness-transport':
                        subprocess.run([runtime,str(root/'tests/sql-witness-transport.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-durable-statements':
                        subprocess.run([runtime,str(root/'tests/sql-durable-statements.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--locked-schema':
                        subprocess.run([runtime,str(root/'tests/locked-schema.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-schema-mdl':
                        subprocess.run([runtime,str(root/'tests/sql-schema-mdl.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-resolution-budget':
                        subprocess.run([runtime,str(root/'tests/sql-resolution-budget.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--schema-clock-context':
                        subprocess.run([runtime,str(root/'tests/schema-clock-context.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--captured-session-expiry':
                        subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/state-boundary/native-maintenance.php'),'mysql','factory','audit_delegation','read-pair'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--audit-window-archive':
                        subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/audit-window-archive.php'),'mysql','all'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--current-worker-context':
                        subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/current-worker-context.php'),'mysql','all'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--current-worker-read':
                        subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/current-worker-read.php'),'mysql','all'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-metadata-statements':
                        subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/sql-metadata-statements.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-schema-visibility':
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/sql-schema-visibility.php')],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/sql-schema-principal.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--mysql-trigger-global-race':
                        for target in ['store','webhook']:
                            subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/mysql-trigger-global-race.php'),target],env=env,check=True)
                        continue
                    if sys.argv[1]=='--mysql-store-visibility':
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/mysql-store-visibility.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-schema-visibility':
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/webhook-schema-visibility.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/webhook-schema.php'),'mysql','canonical'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--webhook-schema':
                        for name in ['webhook-schema','webhook-schema-visibility','webhook-inbox','webhook-request-authority','webhook-clock-failure']:
                            subprocess.run([runtime,'-d','memory_limit=16M',str(root/('tests/'+name+'.php')),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--configuration-presets':
                        subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/preset-shared-budget.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--session-current-authority':
                        subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/session-current-authority.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--mysql-store-triggers':
                        outcomes=[]
                        for mode in ['trigger_insert','trigger_update','trigger_delete','canonical']:
                            for operation in ['construct','transact','prune']:
                                outcomes.append(subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/mysql-store-schema-drift.php'),mode,operation],env=env).returncode)
                        if any(outcomes): raise RuntimeError('Store trigger checks failed: '+str(outcomes))
                        continue
                    if sys.argv[1]=='--mysql-store-schema-drift':
                        outcomes=[]
                        for mode in ['engine','payload','expiry','extra','canonical']:
                            for operation in ['transact','prune']:
                                outcomes.append(subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/mysql-store-schema-drift.php'),mode,operation],env=env).returncode)
                        if any(outcomes): raise RuntimeError('Schema drift checks failed: '+str(outcomes))
                        continue
                    if sys.argv[1]=='--factor-initial-read':
                        for mode in ['normal','binding','account-disabled','account-unverified','account-temporary','account-valid-write','account-delete','account-body','account-root','initial-root-corrupt','initial-body-corrupt','before-denial','current-denial']:
                            subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/factor-initial-read.php'),'mysql',mode],env=env,check=True)
                        for mode in ['normal','missing','other-corrupt','deleted-other','body-corrupt','paged']:
                            subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-initial-checkpoint.php'),'mysql',mode],env=env,check=True)
                        continue
                    if sys.argv[1]=='--factor-checkpoint-read':
                        for mode in ['normal','binding','return-denial','return-account-change','return-body-change']:
                            subprocess.run([runtime,'-d','memory_limit=32M',str(root/'tests/factor-checkpoint-read.php'),'mysql',mode],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-checkpoint-read':
                        for mode in ['normal','missing','changed','other-corrupt','deleted-other','body-corrupt','paged']:
                            subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests/ledger-checkpoint-read.php'),'mysql',mode],env=env,check=True)
                        continue
                    if sys.argv[1]=='--ledger-read-capture':
                        for mode in ['normal','missing','other-corrupt','deleted-other','body-corrupt','paged']:
                            subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/ledger-read-capture.php'), 'mysql', mode], env=env, check=True)
                        continue
                    if sys.argv[1]=='--mysql-store-errors':
                        error_results=[subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/mysql-store-errors.php'), mode], env=env).returncode for mode in ['construct','install','transact','prune']]
                        if any(error_results): raise RuntimeError('Private PDO details exposed: '+str(error_results))
                        continue
                    if sys.argv[1]=='--mysql-store-metadata':
                        for mode in ['canonical','large-extra-defaults','wrong-type']:
                            subprocess.run([runtime, '-d', 'memory_limit=64M', str(root/'tests/mysql-store-metadata.php'), 'prepare', mode], env=env, check=True)
                            subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/mysql-store-metadata.php'), 'read', mode], env=env, check=True)
                        continue
                    if sys.argv[1]=='--mysql-store-extra-index':
                        index_results=[subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/mysql-store-index.php'), mode], env=env).returncode for mode in ['extra-unique','cached-extra-unique']]
                        if any(index_results): raise RuntimeError('Additional private unique index accepted: '+str(index_results))
                        continue
                    if sys.argv[1]=='--mysql-store-regression':
                        subprocess.run([runtime, str(root/'tests/mysql.php')], env=env, check=True)
                        ownership(runtime, env, ['store','prune','install'])
                        continue
                    if sys.argv[1]=='--mysql-store-index':
                        index_results=[subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/mysql-store-index.php'), mode], env=env).returncode for mode in ['canonical','primary-prefix','expiry-prefix','expiry-unique','cached-primary-prefix','cached-expiry-prefix','cached-expiry-unique','extra-unique','cached-extra-unique']]
                        if any(index_results): raise RuntimeError('Private store index acceptance failed: '+str(index_results))
                        continue
                    if sys.argv[1]=='--remember-risk-boundary':
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/remember-risk-boundary.php'),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-schema-pair':
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/sql-schema-pair.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/sql-schema-principal.php'),'pair'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-context':
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/sql-context.php'),'mysql'],env=env,check=True)
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/sql-enlistment.php'),'mysql','transaction-only'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-schema-unexpected-unique':
                        for name in ['sql-schema-unexpected-unique','sql-schema-consumers']:
                            subprocess.run([runtime,'-d','memory_limit=8M',str(root/('tests/'+name+'.php')),'mysql'],env=env,check=True)
                        continue
                    if sys.argv[1]=='--mysql-resolved-table':
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/mysql-resolved-table.php')],env=env,check=True)
                        continue
                    if sys.argv[1]=='--sql-foreign-plan':
                        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/sql-foreign-plan.php'), 'mysql'], env=env, check=True)
                        continue
                    if sys.argv[1] in ['--sql-schema-queries','--sql-schema-index-batch']:
                        for name in (['sql-schema-index-batch','sql-schema-queries','sql-schema-reuse'] if sys.argv[1]=='--sql-schema-index-batch' else ['sql-schema-queries','sql-schema-reuse']):
                            subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/('tests/'+name+'.php')), 'mysql'], env=env, check=True)
                        continue
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/sql-schema-dependencies.php'), 'mysql'], env=env, check=True)
                    continue
                if account_factors:
                    for backend in ['file-store','mysql-store']:
                        subprocess.run(['python3',str(root/'tests/account_factor.py'),runtime,'mysql',backend],env=env,check=True)
                    continue
                if state_codecs:
                    for name in ['account-ledger-mysql', 'account-state-codecs']:
                        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests'/(name+'.php')), 'mysql'], env=env, check=True)
                    for name in ['factory', 'operations', 'migration', 'restoration']:
                        subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/account-factor'/(name+'.php')), 'mysql', 'file-store'], env=env, check=True)
                    continue
                if state_fence_source:
                    subprocess.run(['python3',str(root/'tests/fence_source.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_admission_capacity:
                    subprocess.run(['python3',str(root/'tests/admission_capacity.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_native_hmac:
                    subprocess.run(['python3',str(root/'tests/native_hmac.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_native_reset:
                    subprocess.run(['python3',str(root/'tests/native_reset.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_native_links:
                    subprocess.run(['python3',str(root/'tests/native_links.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_native_grants:
                    names=['grants-native-factory','factory'] if sys.argv[1]=='--state-native-grants-factory' else (['grants-native','grants-native-refusals','grants-native-factory','grants-entry','factory','api-intent'] if sys.argv[1]=='--state-native-grants-basic' else ['grants-native-outcomes'])
                    for name in names:
                        subprocess.run([runtime,'-d','memory_limit=16M',str(root/'tests/state-boundary'/(name+'.php')),'mysql'],env=env,check=True)
                    if sys.argv[1]=='--state-native-grants-outcomes':
                        for name in ['operations','operation-sql']:
                            subprocess.run([runtime,'-d','memory_limit=8M',str(root/'tests'/(name+'.php')),'mysql'],env=env,check=True)
                    continue
                if state_business_crash:
                    subprocess.run(['python3',str(root/'tests/business_crash.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_business_integration:
                    subprocess.run(['python3',str(root/'tests/state_business_integration.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_http:
                    args=['python3',str(root/'tests/state_http.py'),runtime,'--backend','mysql']
                    if sys.argv[1] in ['--state-http-tls','--state-http-business']:args+=['--tls','--browser']
                    if sys.argv[1]=='--state-http-business':args+=['--business']
                    subprocess.run(args,env=env,check=True)
                    continue
                if state_api_business:
                    for name in ['api-business','api-business-refusals','api-business-outcomes','api-native','api-intent','api-intent-formats']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_api_intent:
                    for name in ['api-intent','api-intent-refusals','api-intent-delegation','api-intent-formats']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_api_intent_crash:
                    subprocess.run(['python3',str(root/'tests/api_intent_crash.py'),runtime,'mysql'],env=env,check=True)
                    continue
                if state_api_native:
                    native_suites={'--state-api-native-workflows':['api-native','api-native-factory','api-native-delegation'],'--state-api-native-refusals':['api-native-refusals','api-native-boundary']}
                    for name in native_suites.get(sys.argv[1],['api-native','api-native-refusals','api-native-factory','api-native-delegation','api-native-boundary']):
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_managed_api:
                    for name in ['managed-api-entry','managed-api-retirement','managed-api-resume','managed-api-refusals']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_managed_api_crash:
                    subprocess.run(['python3', str(root/'tests/api_retirement_crash.py'), runtime, 'mysql'], env=dict(env,SOSECURITY_TEST_MANAGED_API='1'), check=True)
                    continue
                if state_api_retirement:
                    for name in ['api-retirement','api-retirement-resume','api-retirement-refusals','api-epoch-backup']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_api_crash:
                    subprocess.run(['python3', str(root/'tests/api_retirement_crash.py'), runtime, 'mysql'], env=env, check=True)
                    continue
                if state_session_failed:
                    for name in ['session-retirement-resume','session-retirement-refusals']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_session_retirement:
                    for name in ['session-retirement','session-retirement-resume','session-retirement-refusals']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_session_crash:
                    session_env=dict(env,SOSECURITY_TEST_INSTALL_SESSIONS='1')
                    subprocess.run(['python3', str(root/'tests/state_crash.py'), runtime, 'mysql', 'before-rename', 'after-rename', 'before-prior', 'after-prior', 'after-session', 'after-sql'], env=session_env, check=True)
                    continue
                if state_crash:
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root/'tests/state-snapshot/staging.php'), 'mysql'], env=env, check=True)
                    subprocess.run(['python3', str(root/'tests/state_crash.py'), runtime, 'mysql'], env=env, check=True)
                    continue
                if state_proof_retirement:
                    subprocess.run(['python3', str(root/'tests/proof_retirement.py'), runtime, 'mysql'], env=env, check=True)
                    continue
                if state_installation_retirement:
                    subprocess.run(['python3', str(root/'tests/installation_retirement.py'), runtime, 'mysql'], env=env, check=True)
                    continue
                if state_installation:
                    for name in ['installation','installation-retirement','installation-resume','installation-refusals','installation-dependencies','installation-audit-compat','installation-legacy-manifests']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_credentials:
                    for name in ['credentials','credentials-refusals','credentials-capacity']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_recovery_audit:
                    for name in ['recovery-audit','recovery-audit-refusals','recovery-audit-capacity']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_account_resolution:
                    for name in ['account-resolution','account-resolution-refusals']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_stale:
                    for name in ['stale-retirement','stale-retirement-refusals']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_budget:
                    subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary/budget-refusals.php'), 'mysql'], env=env, check=True)
                    continue
                if state_requests:
                    subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary/native-requests.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/sql-schema-reuse.php'), 'mysql'], env=env, check=True)
                    continue
                if state_lifecycle:
                    subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary/lifecycle.php'), 'mysql'], env=env, check=True)
                    continue
                if state_factory:
                    subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary/factory.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/account-factor/factory.php'), 'mysql'], env=env, check=True)
                    continue
                if state_entry:
                    for name in ['grants-entry', 'retirement']:
                        subprocess.run([runtime, '-d', 'memory_limit=16M', str(root/'tests/state-boundary'/(name+'.php')), 'mysql'], env=env, check=True)
                    continue
                if state_boundary:
                    subprocess.run(['python3', str(root/'tests/state_boundary.py'), runtime, 'mysql'], env=env, check=True)
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
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/idempotency-input-bounds.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/idempotency-concurrency.php'), 'mysql'], env=env, check=True)
                    continue
                if webhook_processing:
                    subprocess.run([runtime, "-d", "memory_limit=16M", str(root / "tests/webhook-state-access.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/webhook-processing.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/webhook-processing-concurrency.php'), 'mysql'], env=env, check=True)
                    ownership(runtime, env, ['processing','inbox','store','prune','install'])
                    continue
                if webhook_inbox:
                    subprocess.run([runtime, "-d", "memory_limit=8M", str(root / "tests/webhook-request-authority.php"), "mysql"], env=env, check=True)
                    subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/webhook-clock-failure.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/webhook-inbox.php'), 'mysql'], env=env, check=True)
                    subprocess.run([runtime, str(root / 'tests/webhook-inbox-concurrency.php'), 'mysql'], env=env, check=True)
                    ownership(runtime, env, ['inbox'])
                    continue
                for name in ['sql-metadata-statements','webhook-schema','webhook-schema-visibility','mysql-store-visibility','mysql-trigger-global-race','sql-schema-visibility','sql-schema-principal']:
                    subprocess.run([runtime,'-d','memory_limit=16M',str(root/('tests/'+name+'.php')),'mysql'],env=env,check=True)
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
                subprocess.run([runtime, '-d', 'memory_limit=8M', str(root / 'tests/idempotency-input-bounds.php'), 'mysql'], env=env, check=True)
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
