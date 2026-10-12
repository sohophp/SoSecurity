<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli-server' || !getenv('SOSECURITY_TEST_UPLOAD_DIRECTORY')) { http_response_code(404); exit; }
require __DIR__ . '/bootstrap.php';
header('Content-Type: application/json');
header('Cache-Control: no-store');
if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 2097152) { http_response_code(413); echo '{"reason":"upload.request_limit"}'; return; }
try {
    $fault = $_POST['fault'] ?? '';
    $scanner = null;
    if ($fault === 'scanner') {
        $scanner = new class implements SoSecurity\Upload\Scanner {
            public function scan(SoSecurity\Upload\Candidate $c): bool { throw new RuntimeException('DO-NOT-EXPOSE-SCANNER-SECRET'); }
        };
    }
    $saver = new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator(new SoSecurity\Upload\Policy(['maximum_bytes' => 1024])),
        getenv('SOSECURITY_TEST_UPLOAD_DIRECTORY'), __DIR__, $scanner);
    $file = $_FILES['file'] ?? [];
    if ($fault === 'size' && isset($file['size'])) { ++$file['size']; }
    if ($fault === 'fake') { $file['tmp_name'] = getenv('SOSECURITY_TEST_UPLOAD_SOURCE'); }
    $saved = $saver->saveUpload($file);
    http_response_code(201); echo json_encode($saved->metadata());
} catch (SoSecurity\Exception\ValidationException $e) { http_response_code(422); echo json_encode(['reason' => $e->reason()]); }
catch (SoSecurity\Exception\SecurityException $e) { http_response_code(503); echo json_encode(['reason' => $e->reason()]); }
