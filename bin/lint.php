<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$failed = false;
$count = 0;
foreach (['src', 'tests', 'examples', 'demo', 'bin', 'integrations/core-repo'] as $directory) {
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/' . $directory));
    foreach ($iterator as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }
        ++$count;
        exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file->getPathname()) . ' 2>&1', $output, $status);
        if ($status !== 0) {
            fwrite(STDERR, implode("\n", $output) . "\n");
            $failed = true;
        }
        $output = [];
    }
}
echo "PHP " . PHP_VERSION . ": syntax checked $count files\n";
exit($failed ? 1 : 0);
