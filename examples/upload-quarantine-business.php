<?php
declare(strict_types=1);
namespace SoSecurity\Examples\QuarantineHttp;

use PDO;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\PasswordIdentityProvider;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\SqlSchema;

// Inert host composition. The host loads Composer first; import alone performs no I/O.
function privatePath(string $path, string $web, bool $directory = false): string
{
    $real = realpath($path); clearstatcache(true, $path); $stat = @lstat($path);
    if ($real === false || $real !== $path || !is_array($stat) || ($stat['mode'] & 0170000) !== ($directory ? 0040000 : 0100000)
        || ($stat['mode'] & 0777) !== ($directory ? 0700 : 0600) || (!$directory && $stat['nlink'] !== 1)
        || $real === $web || strpos($real, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) {
        throw new ConfigurationException('Use protected canonical private example resources.', 'configuration.quarantine_example');
    }
    return $real;
}
function configuration(string $file, ?string $actualWeb = null): array
{
    clearstatcache(true, $file); $stat = @lstat($file);
    if (!is_array($stat) || ($stat['mode'] & 0170000) !== 0100000 || ($stat['mode'] & 0777) !== 0600 || $stat['nlink'] !== 1 || realpath($file) !== $file || $stat['size'] > 8192) {
        throw new ConfigurationException('Configure a private bounded example configuration.', 'configuration.quarantine_example');
    }
    $raw = @file_get_contents($file, false, null, 0, 8193); $data = is_string($raw) && strlen($raw) <= 8192 ? json_decode($raw, true, 8) : null;
    $fields = ['site', 'origin', 'database', 'state', 'spool', 'document_root', 'socket', 'dummy_hash'];
    if (!is_array($data) || count($data) !== count($fields) || array_diff(array_keys($data), $fields)) { throw new ConfigurationException('Use explicit example configuration.', 'configuration.quarantine_example'); }
    foreach ($fields as $name) { if (!is_string($data[$name]) || $data[$name] === '' || strlen($data[$name]) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $data[$name])) { throw new ConfigurationException('Invalid example setting.', 'configuration.quarantine_example'); } }
    if (!preg_match('/\A[A-Za-z][A-Za-z0-9_.-]{0,63}\z/D', $data['site'])) { throw new ConfigurationException('Use a fixed bounded site.', 'configuration.quarantine_example'); }
    $uri = \SoSecurity\Http\Uri::parse($data['origin']);
    $http = $uri->scheme() === 'http' && getenv('SOSECURITY_QUARANTINE_EXAMPLE_ALLOW_HTTP') === '1' && in_array($uri->hostName(), ['127.0.0.1', 'localhost'], true);
    if ((!$http && $uri->scheme() !== 'https') || $uri->target() !== '/' || rtrim($uri->url(), '/') !== $data['origin']) { throw new ConfigurationException('Use a fixed HTTPS origin.', 'configuration.quarantine_example'); }
    $web = realpath($data['document_root']);
    if ($web === false || $web !== $data['document_root'] || !is_dir($web) || ($actualWeb !== null && realpath($actualWeb) !== $web)) { throw new ConfigurationException('Use the actual canonical Web root.', 'configuration.quarantine_example'); }
    privatePath($file, $web); privatePath($data['database'], $web); privatePath($data['state'], $web, true); privatePath($data['spool'], $web, true);
    $data['secure'] = !$http; return $data;
}
function connection(array $config): PDO
{
    $pdo = new PDO('sqlite:' . $config['database'], null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 1]);
    $pdo->exec('PRAGMA busy_timeout=1000'); return $pdo;
}
function passwordRecord(PDO $pdo, string $site, string $value, bool $username = false): ?PasswordRecord
{
    if (!preg_match('/\A[A-Za-z0-9_.-]{1,64}\z/D', $value)) { return null; }
    $projection = SqlSchema::boundedProjection('sqlite', ['subject' => 'bytes:128', 'password_hash' => 'bytes:255', 'version' => 'bytes:128', 'enabled' => 'int', 'roles' => 'bytes:1024', 'mfa_required' => 'int']);
    $query = $pdo->prepare('SELECT ' . $projection . ' FROM quarantine_example_accounts WHERE site=:site AND ' . ($username ? 'username' : 'subject') . '=:value');
    $query->execute(['site' => $site, 'value' => $value]); $row = $query->fetch(PDO::FETCH_ASSOC); $query->closeCursor();
    if ($row === false) { return null; }
    foreach (['subject', 'password_hash', 'version', 'roles'] as $field) { if (!is_string($row[$field])) { throw new StorageException('Invalid example account.', 'quarantine.source'); } }
    $enabled = SqlSchema::integer($row['enabled']); $mfa = SqlSchema::integer($row['mfa_required']); $roles = json_decode($row['roles'], true, 4);
    if (!in_array($enabled, [0, 1], true) || !in_array($mfa, [0, 1], true) || !is_array($roles) || array_values($roles) !== $roles || !preg_match('/\A[A-Za-z0-9_.-]{1,64}\z/D', $row['subject'])) { throw new StorageException('Invalid example account policy.', 'quarantine.source'); }
    return new PasswordRecord(new Account($site, $row['subject'], $row['version'], $enabled === 1, $roles, $mfa === 1), $row['password_hash']);
}
function services(array $config): array
{
    $pdo = connection($config); $store = new FileStore($config['state'], $config['site'] . ':native-upload');
    $provider = new PasswordIdentityProvider(
        static function (string $site, string $username) use ($pdo): ?PasswordRecord { return passwordRecord($pdo, $site, $username, true); },
        static function (string $site, string $subject) use ($pdo): ?PasswordRecord { return passwordRecord($pdo, $site, $subject); },
        new \SoSecurity\Password\PasswordHasher(), $config['dummy_hash']);
    $scanner = new \SoSecurity\Upload\ClamAvScanner($config['socket'], 5000, 1048576);
    $security = \SoSecurity\Security::fromArray(['site' => $config['site'], 'storage' => ['driver' => 'file', 'directory' => $config['state']],
        'upload_quarantine' => ['directory' => $config['spool'], 'document_root' => $config['document_root'], 'scanner' => 'engine',
            'policy' => ['extensions' => ['txt', 'png', 'pdf'], 'maximum_bytes' => 1048576],
            'queue' => ['maximum_entries' => 64, 'maximum_total_bytes' => 16777216, 'maximum_attempts' => 3,
                'retry_seconds' => 1, 'lease_seconds' => 15, 'scan_milliseconds' => 10000, 'lifetime_seconds' => 86400]]], ['engine' => $scanner]);
    return ['pdo' => $pdo, 'store' => $store, 'provider' => $provider, 'sessions' => new SessionRegistry($store, $provider), 'queue' => $security->quarantine()];
}
function fileId($id): string
{
    if (!is_string($id) || !preg_match('/\A[a-f0-9]{32}\z/D', $id)) { throw new \SoSecurity\Exception\ValidationException('Invalid file reference.', 'quarantine.input'); }
    return $id;
}
function resource(PDO $pdo, string $site, string $id): ?array
{
    $projection = SqlSchema::boundedProjection('sqlite', ['id' => 'id', 'owner' => 'bytes:128', 'created_at' => 'int']);
    $query = $pdo->prepare('SELECT ' . $projection . ' FROM quarantine_example_files WHERE site=:site AND id=:id');
    $query->execute(['site' => $site, 'id' => $id]); $row = $query->fetch(PDO::FETCH_ASSOC); $query->closeCursor();
    if ($row === false) { return null; }
    if ($row['id'] !== $id || !is_string($row['owner']) || !preg_match('/\A[A-Za-z0-9_.-]{1,64}\z/D', $row['owner'])) { throw new StorageException('Invalid file index.', 'quarantine.source'); }
    SqlSchema::integer($row['created_at']); return $row;
}
function current(array $services, array $config): ?\SoSecurity\Auth\VerifiedSession
{
    $subject = $_SESSION['quarantine_subject'] ?? null; $token = $_SESSION['quarantine_token'] ?? null;
    return is_string($subject) && is_string($token) ? $services['sessions']->verify($config['site'], $subject, $token) : null;
}
function permitted(?\SoSecurity\Auth\VerifiedSession $identity, ?array $file, bool $admin = false): bool
{
    if ($identity === null || $file === null) { return false; }
    $account = $identity->account();
    return $admin ? in_array('upload-admin', $account->roles(), true) && $identity->recent(300, time(), 1)
        : in_array('uploader', $account->roles(), true) && hash_equals($account->subject(), $file['owner']);
}
function files(array $services, array $config, \SoSecurity\Auth\VerifiedSession $identity): array
{
    $admin = in_array('upload-admin', $identity->account()->roles(), true); $parameters = ['site' => $config['site']];
    $projection = SqlSchema::boundedProjection('sqlite', ['id' => 'id']);
    $query = $services['pdo']->prepare('SELECT ' . $projection . ' FROM quarantine_example_files WHERE site=:site' . ($admin ? '' : ' AND owner=:owner') . ' ORDER BY created_at,id LIMIT 65');
    if (!$admin) { $parameters['owner'] = $identity->account()->subject(); }
    $query->execute($parameters); $ids = $query->fetchAll(PDO::FETCH_COLUMN); $query->closeCursor();
    if (count($ids) > 64) { throw new StorageException('File index requires maintenance.', 'quarantine.capacity'); }
    $result = [];
    foreach ($ids as $id) {
        if (!is_string($id) || !preg_match('/\A[a-f0-9]{32}\z/D', $id)) { throw new StorageException('Invalid file index identifier.', 'quarantine.source'); }
        $id = fileId($id); $row = resource($services['pdo'], $config['site'], $id);
        if ($row === null || (!$admin && !permitted($identity, $row))) { continue; }
        $status = $services['queue']->inspect($id);
        if ($status === null) { throw new StorageException('File index disagrees with quarantine.', 'quarantine.source'); }
        $result[] = ['id' => $id, 'state' => $status->state(), 'download' => permitted($identity, $row), 'manage' => permitted($identity, $row, true)];
    }
    return $result;
}
