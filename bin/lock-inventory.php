<?php
declare(strict_types=1);

/** Read-only, deterministic inventory of one Composer manifest and its exact lock file. */
function inventoryFail(string $message): void
{
    fwrite(STDERR, 'lock-inventory: ' . $message . "\n");
    exit(1);
}

function inventoryLocation(?array $location, bool $allowLocalPath): ?array
{
    if ($location === null) { return null; }
    $type = $location['type'] ?? null;
    $url = $location['url'];
    if (!is_string($type) || strlen($url) > 2048 || preg_match('/[\x00-\x1f\x7f]/', $url)) {
        inventoryFail('Locked package source URL is invalid.');
    }
    if ($allowLocalPath && $type === 'path') {
        if ($url === '' || strpos($url, '?') !== false || strpos($url, '#') !== false) {
            inventoryFail('Local package path is invalid.');
        }
        return ['type' => 'path', 'url' => '[local-path]', 'reference' => $location['reference']];
    }
    $parsed = parse_url($url);
    if (!is_array($parsed) || !isset($parsed['scheme'], $parsed['host'])
        || !in_array(strtolower($parsed['scheme']), ['https', 'ssh', 'git'], true)
        || isset($parsed['user']) || isset($parsed['pass']) || isset($parsed['query']) || isset($parsed['fragment'])) {
        inventoryFail('Locked package source URL contains credentials or unsupported components.');
    }
    return ['type' => $type, 'url' => $url, 'reference' => $location['reference']];
}

if (PHP_SAPI !== 'cli' || $argc > 2) { inventoryFail('Pass one local Composer project directory.'); }
$directory = realpath($argv[1] ?? dirname(__DIR__));
if ($directory === false || !is_dir($directory)) { inventoryFail('Project directory is unavailable.'); }
$manifestPath = $directory . '/composer.json';
$lockPath = $directory . '/composer.lock';
if (!is_file($manifestPath) || !is_file($lockPath) || is_link($manifestPath) || is_link($lockPath)) {
    inventoryFail('An ordinary composer.json and composer.lock pair is required.');
}
$manifestSize = filesize($manifestPath);
$lockSize = filesize($lockPath);
if ($manifestSize === false || $lockSize === false || $manifestSize > 1048576 || $lockSize > 8388608) {
    inventoryFail('Composer inputs exceed the read budget.');
}
$manifestBytes = file_get_contents($manifestPath, false, null, 0, $manifestSize + 1);
$lockBytes = file_get_contents($lockPath, false, null, 0, $lockSize + 1);
if (!is_string($manifestBytes) || !is_string($lockBytes)
    || strlen($manifestBytes) > 1048576 || strlen($lockBytes) > 8388608) {
    inventoryFail('Composer inputs are unavailable or exceed the read budget.');
}
$manifest = json_decode($manifestBytes, true, 64);
$lock = json_decode($lockBytes, true, 64);
if (!is_array($manifest) || !is_array($lock)
    || !isset($manifest['name'], $manifest['require'], $lock['packages'], $lock['packages-dev'], $lock['content-hash'])
    || !is_string($manifest['name']) || !is_array($manifest['require'])
    || !is_array($lock['packages']) || !is_array($lock['packages-dev'])
    || !is_string($lock['content-hash']) || !preg_match('/\A[a-f0-9]{32}\z/D', $lock['content-hash'])) {
    inventoryFail('Composer manifest or lock shape is invalid.');
}
$packages = [];
$seen = [];
foreach (['packages' => 'runtime', 'packages-dev' => 'development'] as $section => $role) {
    foreach ($lock[$section] as $package) {
        if (!is_array($package) || !isset($package['name'], $package['version'])
            || !is_string($package['name']) || !is_string($package['version'])
            || !preg_match('/\A[a-z0-9_.-]+\/[a-z0-9_.-]+\z/D', $package['name'])
            || isset($seen[$package['name']])) {
            inventoryFail('Invalid or duplicate locked package.');
        }
        $seen[$package['name']] = true;
        $source = $package['source'] ?? null;
        $dist = $package['dist'] ?? null;
        if (($source !== null && (!is_array($source) || !isset($source['url'], $source['reference'])
                || !is_string($source['url']) || !is_string($source['reference'])))
            || ($dist !== null && (!is_array($dist) || !isset($dist['url'], $dist['reference'])
                || !is_string($dist['url']) || !is_string($dist['reference'])))) {
            inventoryFail('Locked package source is malformed.');
        }
        $licenses = $package['license'] ?? [];
        $requires = $package['require'] ?? [];
        if (!is_array($licenses) || !is_array($requires)) { inventoryFail('Locked package metadata is malformed.'); }
        foreach ($licenses as $license) {
            if (!is_string($license)) { inventoryFail('Locked package license is malformed.'); }
        }
        foreach ($requires as $name => $constraint) {
            if (!is_string($name) || !is_string($constraint)) { inventoryFail('Locked package requirement is malformed.'); }
        }
        ksort($requires, SORT_STRING);
        $packages[] = ['name' => $package['name'], 'version' => $package['version'], 'role' => $role,
            'license' => array_values($licenses), 'source' => inventoryLocation($source, false),
            'dist' => inventoryLocation($dist, true),
            'require' => $requires];
    }
}
usort($packages, static function (array $left, array $right): int {
    return strcmp($left['name'], $right['name']);
});
$rootRequires = $manifest['require'];
$rootDevRequires = $manifest['require-dev'] ?? [];
if (!is_array($rootDevRequires)) { inventoryFail('Root development requirements are malformed.'); }
foreach ([$rootRequires, $rootDevRequires] as $requirements) {
    foreach ($requirements as $name => $constraint) {
        if (!is_string($name) || !is_string($constraint)) { inventoryFail('Root requirement is malformed.'); }
    }
}
ksort($rootRequires, SORT_STRING);
ksort($rootDevRequires, SORT_STRING);
$result = ['format' => 'sosecurity.lock-inventory.v1',
    'manifest_sha256' => hash('sha256', $manifestBytes), 'lock_sha256' => hash('sha256', $lockBytes),
    'lock_content_hash' => $lock['content-hash'],
    'root' => ['name' => $manifest['name'], 'license' => $manifest['license'] ?? null,
        'require' => $rootRequires, 'require_dev' => $rootDevRequires],
    'packages' => $packages];
$encoded = json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
if (!is_string($encoded)) { inventoryFail('Cannot encode inventory.'); }
echo $encoded . "\n";
