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
        expected_sources = {str(path.relative_to(root)) for path in (root / 'src').rglob('*.php')}
        assert {name for name in names if name.startswith('src/') and name.endswith('.php')} == expected_sources
        assert all(name in names for name in ['src/Audit/AuditLogger.php', 'src/Audit/BudgetedSink.php',
                                             'src/Audit/MetricsSink.php', 'docs/audit-budget.md'])
        assert all('src/Account/'+name+'.php' in names for name in ['StateSnapshot','StateStoreSource','StateStorageDomain','SqlStateSnapshot','SqlStateCapture','FileStateSnapshot','FileStateCapture','CompositeStateSnapshot','CompositeStateCapture'])
        assert all(name in names for name in ['examples/state-snapshot.php','docs/state-snapshots.md','docs/state-snapshots.en.md','resources/sql/state-snapshot-example-sqlite.sql','resources/sql/state-snapshot-example-mysql.sql'])
        assert all(name in names for name in ['src/Upload/ClamAvScanner.php','examples/clamav-scanner.php','docs/upload-scanning.md','docs/upload-scanning.en.md'])
        assert all(name in names for name in ['src/Upload/ArchiveInspector.php','examples/archive-inspection.php','docs/archive-inspection.md','docs/archive-inspection.en.md'])
        assert all('src/Upload/'+name+'.php' in names for name in ['Quarantine','QuarantineStatus','QuarantineState','QuarantineFiles'])
        assert all(name in names for name in ['examples/upload-quarantine.php','docs/upload-quarantine.md','docs/upload-quarantine.en.md'])
        assert all(name in names for name in ['examples/upload-quarantine-business.php','examples/upload-quarantine-http.php','examples/upload-quarantine-worker.php','resources/sql/upload-quarantine-example-sqlite.sql','docs/upload-quarantine-native.md','docs/upload-quarantine-native.en.md'])
        assert 'examples/account-mail-worker.php' in names
        assert 'src/Account/FactorNotices.php' in names
        assert 'composer.json' in names and 'LICENSE' in names and 'src/Csrf/CsrfTokens.php' in names and 'resources/sql/mysql.sql' in names and 'src/Validation/Validator.php' in names and 'src/Upload/Saver.php' in names and 'src/Http/Outbound/Client.php' in names
        assert 'src/Api/HmacVerifier.php' in names and 'src/Api/ApiKeys.php' in names and 'examples/api-request.php' in names
        assert all('src/Api/'+name+'.php' in names for name in ['CredentialPolicy','CredentialInfo','IssuedCredential','VerifiedCredential','CredentialRegistry','CredentialEncoding','CredentialState'])
        assert 'docs/api-credentials.md' in names
        assert 'examples/api-credentials.php' in names
        assert all('src/Webhook/'+name+'.php' in names for name in ['Endpoint','KeySet','Request','VerifiedWebhook','Verifier','Wire'])
        assert 'docs/webhooks.md' in names
        assert all('src/Webhook/'+name+'.php' in names for name in ['Message','Receipt','SqlInbox','InboxState','InboxSchema'])
        assert 'resources/sql/webhook-mysql.sql' in names and 'resources/sql/webhook-sqlite.sql' in names
        assert 'examples/webhooks.php' in names
        assert all('src/Webhook/'+name+'.php' in names for name in ['ProcessingPolicy','ProcessingStatus','ProcessingClaim','ProcessingState','ProcessingSchema','SqlProcessor'])
        assert 'docs/webhook-processing.md' in names
        assert all('src/Idempotency/'+name+'.php' in names for name in ['Policy','Request','Response','Outcome','SqlExecutor','State','Schema'])
        assert all('src/Support/'+name+'.php' in names for name in ['SqlTransaction','SqlSchema'])
        assert all('resources/sql/idempotency-'+driver+'.sql' in names for driver in ['sqlite','mysql'])
        assert 'docs/idempotency.md' in names
        assert all('src/Outbox/'+name+'.php' in names for name in ['Policy','Message','Status','Claim','SqlOutbox','State','Schema'])
        assert all('resources/sql/outbox-'+driver+'.sql' in names for driver in ['sqlite','mysql'])
        assert 'docs/outbox.md' in names
        assert all('src/Account/'+name+'.php' in names for name in ['Address','Policy','Notice','Notifications'])
        assert 'docs/account-notifications.md' in names
        assert all('src/Account/'+name+'.php' in names for name in ['AccountRecord','Repository','IdentityRepository','Ledger','Delivery','ChangeDelivery','Registration','AddressChange'])
        assert 'src/Account/RequestBudgets.php' in names
        assert all('src/Account/'+name+'.php' in names for name in ['Recovery','RecoveryDelivery'])
        assert 'docs/account-recovery.md' in names
        assert all('src/Account/'+name+'.php' in names for name in ['FactorRegistry','ManagedSecondFactor','FactorRestoration'])
        assert 'docs/account-factors.md' in names and 'docs/managed-authentication-native.md' in names
        assert 'examples/managed-authentication.php' in names
        assert all('resources/sql/account'+suffix+'-'+driver+'.sql' in names for suffix in ['', '-example'] for driver in ['sqlite','mysql'])
        assert 'examples/SqlAccounts.php' in names and 'docs/account-lifecycle.md' in names
        assert 'docs/outbox-native.md' in names
        assert 'docs/outbox-recovery.md' in names
        assert 'docs/outbox-reconciliation.md' in names
        assert all('examples/outbox-'+name+'.php' in names for name in ['business','producer','worker','admin','receiver','receiver-admin','recovery','resolution','resolution-archive','authority'])
        assert 'resources/sql/outbox-example-authority-sqlite.sql' in names
        assert 'docs/outbox-authority.md' in names
        assert all('resources/sql/outbox-example-'+role+'-sqlite.sql' in names for role in ['sender','receiver','checkpoint'])
        assert all('resources/sql/outbox-example-resolution-'+role+'-sqlite.sql' in names for role in ['sender','receiver'])
        assert 'resources/sql/outbox-example-resolution-archive-sqlite.sql' in names
        assert 'docs/outbox-audit-archive.md' in names
        assert 'docs/idempotency-native.md' in names
        assert all('examples/'+name+'.php' in names for name in ['idempotency','idempotency-admin','idempotency-business'])
        assert 'examples/idempotency.js' in names and 'resources/sql/idempotency-example-sqlite.sql' in names
        assert all('examples/'+name+'.php' in names for name in ['webhook-worker','webhook-business'])
        assert 'resources/sql/webhook-example-processing-sqlite.sql' in names
        assert all('resources/sql/webhook-processing-'+driver+'.sql' in names for driver in ['sqlite','mysql'])
        assert 'src/Csrf/SignedTokens.php' in names and 'src/Support/HmacKeys.php' in names and 'src/Csrf/RequestPolicy.php' in names
        assert 'examples/configuration-presets.php' in names and 'docs/index.md' in names and 'docs/features.md' in names and 'docs/requirements.md' in names
        assert 'examples/signed-form.php' in names and 'src/Output/HtmlCleaner.php' in names and 'examples/rich-text.php' in names
        assert 'docs/captcha.md' in names and 'examples/captcha-types.php' in names and 'src/Captcha/HCaptcha.php' in names and 'src/Captcha/Recaptcha.php' in names
        assert all('src/Operation/'+name+'.php' in names for name in ['Policy','Intent','Confirmation','Grant','Permit','Grants','Shape','State'])
        assert 'examples/operation-work.php' in names and 'examples/operation-authorization.php' in names and 'docs/operations.md' in names
        assert all('src/Link/'+name+'.php' in names for name in ['Policy','Target','IssuedLink','VerifiedLink','Links','Encoding','State'])
        assert 'examples/signed-links.php' in names and 'docs/signed-links.md' in names
        assert all('src/Download/'+name+'.php' in names for name in ['Policy','File','Request','RangeException','Access','Grant','SessionAccess','LinkAccess','Transfer','Downloads','Selection','Time','Snapshot','LocalReader'])
        assert 'examples/authorized-download.php' in names and 'docs/downloads.md' in names
        unexpected = [name for name in names if name.startswith(('vendor/', 'tools/', 'integrations/', 'resources/api/', 'tests/', 'bin/', 'demo/', '.git/', '.github/', '.phpstan-cache/', 'var/'))]
        assert not unexpected, unexpected[:10]
        assert not any(name.endswith(('.env', '.log', 'composer.lock')) for name in names)
        print(f'PASS archive: {len(names)} package files; no vendor/development artifacts/private configuration filenames')
