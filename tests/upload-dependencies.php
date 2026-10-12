<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Exception\DependencyException;

if (!extension_loaded('fileinfo')) {
    Check::throws(DependencyException::class, function () { new SoSecurity\Upload\Validator(); });
} elseif (!extension_loaded('gd')) {
    $directory = privateDirectory();
    try {
        $bytes = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAC0lEQVQImWNgQAYAAA4AAbGa6gYAAAAASUVORK5CYII=');
        file_put_contents($directory . '/image', $bytes);
        Check::throws(DependencyException::class, function () use ($directory) { (new SoSecurity\Upload\Validator())->inspectFile($directory . '/image', 'photo.png'); });
        file_put_contents($directory . '/text', "text\n");
        Check::same('text/plain', (new SoSecurity\Upload\Validator(new SoSecurity\Upload\Policy(['extensions' => ['txt']])))->inspectFile($directory . '/text', 'note.txt')->mime());
    } finally { cleanDirectory($directory); }
} else { echo "NOT RUN upload missing dependency: run without fileinfo or GD\n"; exit(0); }
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " missing upload dependency assertions passed\n";
