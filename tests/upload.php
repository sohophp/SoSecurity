<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Upload\Policy;
use SoSecurity\Upload\Validator;
use SoSecurity\Upload\Saver;
use SoSecurity\Upload\Scanner;
use SoSecurity\Upload\Candidate;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

$source = privateDirectory(); $target = privateDirectory(); $web = privateDirectory();
try {
    if (!extension_loaded('fileinfo') || !extension_loaded('gd')) { echo "NOT RUN upload image integration: fileinfo and GD required\n"; exit(getenv('SOSECURITY_REQUIRE_UPLOAD') === '1' ? 1 : 0); }
    $image = imagecreatetruecolor(2, 2); imagepng($image, $source . '/image'); if (is_resource($image)) { imagedestroy($image); } unset($image);
    $png = file_get_contents($source . '/image'); $policy = new Policy(); $validator = new Validator($policy);
    $candidate = $validator->inspectFile($source . '/image', '测试.v2.PNG');
    Check::same('image/png', $candidate->mime()); Check::same(2, $candidate->width()); Check::same(2, $candidate->height());
    Check::same(hash('sha256', $candidate->contents()), $candidate->digest());
    $saver = new Saver($validator, $target, $web); $before = ob_get_level(); ob_start();
    $saved = $saver->saveFile($source . '/image', 'safe.png'); $output = ob_get_clean();
    Check::same('', $output); Check::same($before, ob_get_level());
    Check::same(0600, fileperms($saved->path()) & 0777); Check::same(true, is_file($source . '/image'));
    Check::same(true, (bool) preg_match('/^[a-f0-9]{32}\.png$/D', $saved->metadata()['filename']));
    Check::same(false, array_key_exists('path', $saved->metadata())); Check::same(false, $saved->metadata()['scanner_passed']);
    foreach (['../x.png', '/x.png', 'x\\x.png', 'x:ads.png', 'x.php.png', '.htaccess.png', 'CON.png', 'x.png.', 'x.png ', "x\x00.png", "x\xff.png", "x\xe2\x80\xae.png", 'x%2e.png'] as $name) {
        Check::throws(ValidationException::class, function () use ($validator, $source, $name) { $validator->inspectFile($source . '/image', $name); });
    }
    foreach (['x.php', 'x.svg', 'x.zip', 'x.jpg'] as $name) {
        Check::throws(ValidationException::class, function () use ($validator, $source, $name) { $validator->inspectFile($source . '/image', $name); });
    }
    file_put_contents($source . '/script', '<?php echo "executable";');
    Check::throws(ValidationException::class, function () use ($validator, $source) { $validator->inspectFile($source . '/script', 'photo.png'); });
    symlink($source . '/image', $source . '/link');
    Check::throws(ValidationException::class, function () use ($validator, $source) { $validator->inspectFile($source . '/link', 'photo.png'); });
    Check::throws(ValidationException::class, function () use ($validator, $source) { $validator->inspectFile('file://' . $source . '/image', 'photo.png'); });
    file_put_contents($source . '/huge', str_repeat('a', 1025));
    Check::throws(ValidationException::class, function () use ($source) { (new Validator(new Policy(['maximum_bytes' => 1024])))->inspectFile($source . '/huge', 'photo.png'); });
    // A plausible huge PNG header must be rejected before decoder allocation.
    $ihdr = pack('NNCCCCC', 60000, 60000, 8, 2, 0, 0, 0);
    $huge = "\x89PNG\r\n\x1a\n" . pack('N', 13) . 'IHDR' . $ihdr . pack('N', crc32('IHDR' . $ihdr));
    file_put_contents($source . '/geometry', $huge);
    try { $validator->inspectFile($source . '/geometry', 'photo.png'); throw new RuntimeException('Huge dimensions passed'); }
    catch (ValidationException $e) { Check::same('upload.image_budget', $e->reason()); }
    file_put_contents($source . '/broken', substr($png, 0, 40));
    Check::throws(ValidationException::class, function () use ($validator, $source) { $validator->inspectFile($source . '/broken', 'photo.png'); });
    file_put_contents($source . '/polyglot', $png . '<?php PHRASE_SHOULD_NOT_SURVIVE_REENCODING ?>');
    $clean = $saver->saveFile($source . '/polyglot', 'photo.png');
    Check::same(false, strpos(file_get_contents($clean->path()), 'PHRASE_SHOULD_NOT_SURVIVE_REENCODING') !== false);
    Check::same(true, strpos(file_get_contents($source . '/polyglot'), 'PHRASE_SHOULD_NOT_SURVIVE_REENCODING') !== false);
    Check::throws(ValidationException::class, function () use ($validator, $source) { $validator->inspectUpload(['name' => 'photo.png', 'tmp_name' => $source . '/image', 'size' => filesize($source . '/image'), 'error' => 0]); });
    Check::throws(ValidationException::class, function () use ($validator) { $validator->inspectUpload(['error' => []]); });
    foreach ([UPLOAD_ERR_PARTIAL, UPLOAD_ERR_NO_FILE, UPLOAD_ERR_INI_SIZE] as $error) {
        Check::throws(ValidationException::class, function () use ($validator, $error) { $validator->inspectUpload(['name' => '', 'tmp_name' => '', 'size' => 0, 'error' => $error]); });
    }
    Check::throws(StorageException::class, function () use ($validator) { $validator->inspectUpload(['name' => '', 'tmp_name' => '', 'size' => 0, 'error' => UPLOAD_ERR_CANT_WRITE]); });
    foreach ([['extensions' => ['svg']], ['extensions' => ['png','png']], ['maximum_bytes' => null], ['maximum_width' => 0], ['require_scan' => 'yes'], ['unknown' => true]] as $bad) {
        Check::throws(ConfigurationException::class, function () use ($bad) { new Policy($bad); });
    }
    $bytes = 1024; $extensions = ['png']; $frozen = new Policy(['maximum_bytes' => &$bytes, 'extensions' => &$extensions]);
    $bytes = 0; $extensions[] = 'pdf'; Check::same(1024, $frozen->maximumBytes()); Check::same(null, $frozen->mime('pdf'));
    Check::throws(ConfigurationException::class, function () use ($frozen) { $frozen->maximum_bytes = 0; });
    Check::throws(ConfigurationException::class, function () use ($candidate) { $candidate->contents = 'evil'; });
    Check::throws(ConfigurationException::class, function () use ($validator, $web) { new Saver($validator, $web, $web); });
    chmod($target, 0755);
    Check::throws(StorageException::class, function () use ($validator, $target, $web) { new Saver($validator, $target, $web); }); chmod($target, 0700);
    $required = new Validator(new Policy(['require_scan' => true]));
    Check::throws(ConfigurationException::class, function () use ($required, $target, $web) { new Saver($required, $target, $web); });
    $reject = new class implements Scanner { public function scan(Candidate $c): bool { return false; } };
    $crash = new class implements Scanner { public function scan(Candidate $c): bool { throw new RuntimeException('private scanner failure'); } };
    $count = count(glob($target . '/*'));
    Check::throws(ValidationException::class, function () use ($required, $target, $web, $source, $reject) { (new Saver($required, $target, $web, $reject))->saveFile($source . '/image', 'photo.png'); });
    Check::throws(SecurityException::class, function () use ($required, $target, $web, $source, $crash) { (new Saver($required, $target, $web, $crash))->saveFile($source . '/image', 'photo.png'); });
    Check::same($count, count(glob($target . '/*')));
    $changeSource = new class($source . '/image') implements Scanner {
        private $source;
        public function __construct(string $source) { $this->source = $source; }
        public function scan(Candidate $c): bool { file_put_contents($this->source, 'malicious changed source'); return true; }
    };
    $snapshot = (new Saver($required, $target, $web, $changeSource))->saveFile($source . '/image', 'photo.png');
    Check::same('image/png', (new finfo(FILEINFO_MIME_TYPE))->file($snapshot->path()));
    Check::same(true, $snapshot->metadata()['scanner_passed']);
    $documents = new Validator(new Policy(['extensions' => ['txt', 'pdf']]));
    file_put_contents($source . '/text', "中文测试\nplain text\n");
    Check::same('text/plain', $documents->inspectFile($source . '/text', 'note.txt')->mime());
    file_put_contents($source . '/pdf', "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n");
    Check::same('application/pdf', $documents->inspectFile($source . '/pdf', 'test.pdf')->mime());
    file_put_contents($source . '/badpdf', "%PDF-1.7\nmissing end\n");
    Check::throws(ValidationException::class, function () use ($documents, $source) { $documents->inspectFile($source . '/badpdf', 'test.pdf'); });
    file_put_contents($source . '/image', $png);
    $factory = SoSecurity\Security::fromArray(['site' => 'upload-test', 'upload' => ['directory' => $target, 'document_root' => $web]]);
    Check::same('image/png', $factory->uploader()->saveFile($source . '/image', 'photo.png')->metadata()['mime']);
    Check::same('pass', array_column($factory->diagnose($web), null, 'check')['upload.location']['status']);
    Check::same('fail', array_column($factory->diagnose($source), null, 'check')['upload.location']['status']);
    Check::same(false, strpos(json_encode($factory->diagnose()), $target) !== false);
    Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site' => 'a'])->uploader(); });
    foreach ([null, [], ['directory' => $target, 'document_root' => $web, 'maximum_bytes' => null], ['directory' => $target, 'document_root' => $web, 'scanner' => null]] as $bad) {
        Check::throws(ConfigurationException::class, function () use ($bad) { SoSecurity\Security::fromArray(['site' => 'a', 'upload' => $bad]); });
    }
    Check::throws(ValidationException::class, function () use ($source) { (new Validator(new Policy(['working_bytes' => 1048576])))->inspectFile($source . '/image', 'photo.png'); });
    require dirname(__DIR__) . '/examples/upload-adapter.php';
    Check::same('image/png', SoSecurity\Examples\inspectManagedUpload($validator, $source . '/image', 'photo.png')->mime());
    $image = imagecreatetruecolor(3, 2); imagejpeg($image, $source . '/jpeg', 90);
    if (function_exists('imagewebp') && (imagetypes() & IMG_WEBP)) { imagewebp($image, $source . '/webp', 90); }
    if (is_resource($image)) { imagedestroy($image); } unset($image);
    if ($candidate->bytes() > strlen($png)) {
        $limited = new Validator(new Policy(['maximum_bytes' => strlen($png)]));
        try { $limited->inspectFile($source . '/image', 'photo.png'); throw new RuntimeException('Oversized encoding passed'); }
        catch (ValidationException $e) { Check::same('upload.too_large', $e->reason()); }
    }
    file_put_contents($source . '/pdf2', "%PDF-2.0\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n");
    Check::same('application/pdf', $documents->inspectFile($source . '/pdf2', 'test.pdf')->mime());
    $jpeg = $saver->saveFile($source . '/jpeg', 'photo.jpeg');
    Check::same('image/jpeg', $jpeg->metadata()['mime']); Check::same(3, $jpeg->metadata()['width']);
    Check::same(true, substr($jpeg->path(), -4) === '.jpg');
    if (is_file($source . '/webp')) {
        $webp = (new Validator(new Policy(['extensions' => ['webp']]), $target))->inspectFile($source . '/webp', 'photo.webp');
        Check::same('image/webp', $webp->mime()); Check::same(3, $webp->width());
        $webpSaved = (new Saver(new Validator(new Policy(['extensions' => ['webp']])), $target, $web))->saveFile($source . '/webp', 'photo.webp');
        Check::same('image/webp', $webpSaved->metadata()['mime']); Check::same([], glob($target . '/.decode-*'));
        if (PHP_VERSION_ID < 70300) {
            Check::throws(SoSecurity\Exception\DependencyException::class, function () use ($source) { (new Validator(new Policy(['extensions' => ['webp']])))->inspectFile($source . '/webp', 'photo.webp'); });
        }
    } else { echo "NOT RUN WebP upload: actual GD codec support required\n"; }
    echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " upload assertions passed\n";
} finally { cleanDirectory($source); cleanDirectory($target); cleanDirectory($web); }
