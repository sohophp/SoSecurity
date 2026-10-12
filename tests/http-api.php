<?php
declare(strict_types=1);
// Isolated test-only server router, bound to 127.0.0.1 by api_http.py; never included in the public demo/archive.
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/examples/api-request.php';
header('Content-Type: application/json'); header('Cache-Control: no-store');
$directory=getenv('SOSECURITY_TEST_API_STORAGE'); $origin=getenv('SOSECURITY_TEST_API_ORIGIN');
if (!$directory || !$origin) { http_response_code(503); echo '{}'; return; }
$store=new SoSecurity\Storage\FileStore($directory,'http-api');
$limiter=new SoSecurity\RateLimit\RateLimiter($store,new SoSecurity\RateLimit\Policy(200,60));
if (!$limiter->consume('entry',$_SERVER['REMOTE_ADDR'])->allowed) { http_response_code(429); echo '{}'; return; }
$key=new SoSecurity\Api\SigningKey('python-http-key',str_repeat('k',32),'http-client',['task:read']);
$policy=new SoSecurity\Api\SignaturePolicy(['origin'=>$origin,'allow_http'=>true,'maximum_body'=>1024,'clock_skew'=>0]);
$apiKeys=new SoSecurity\Api\ApiKeys($store);
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
try {
    if ($path==='/test-issue' && $_SERVER['REQUEST_METHOD']==='POST') {
        $credential=$apiKeys->issue('http-client',['task:read'],60); echo json_encode(['token'=>$credential->token(),'id'=>$credential->identity()->id()]); return;
    }
    if ($path==='/test-revoke' && $_SERVER['REQUEST_METHOD']==='POST') {
        echo json_encode(['revoked'=>$apiKeys->revoke($_POST['id'])]); return;
    }
    if ($path==='/bearer') { $identity=$apiKeys->fromAuthorization($_SERVER['HTTP_AUTHORIZATION'] ?? null,'task:read'); }
    elseif ($path==='/signed' || $path==='/signed-write') {
        $raw=file_get_contents('php://input',false,null,0,1025);
        if (!is_string($raw) || strlen($raw)>1024) { http_response_code(413); echo '{}'; return; }
        $provider=new SoSecurity\Api\KeyRing([$key]);
        if (isset($_GET['fault']) && $_GET['fault']==='provider') {
            $provider=new class implements SoSecurity\Api\KeyProvider { public function find(string $id): ?SoSecurity\Api\SigningKey { throw new RuntimeException('private provider error'); } };
        }
        $nonceStore=$store;
        if (isset($_GET['fault']) && $_GET['fault']==='store') {
            $nonceStore=new class implements SoSecurity\Storage\AtomicStore { public function transact(string $key,callable $callback) { throw new SoSecurity\Storage\StorageException('private store error'); } };
        }
        $verifier=new SoSecurity\Api\HmacVerifier($policy,$provider,new SoSecurity\Api\NonceStore($nonceStore));
        $identity=SoSecurity\Examples\authenticateSignedRequest($verifier,$_SERVER['REQUEST_METHOD'],$origin,$_SERVER['REQUEST_URI'],$raw,getallheaders(),$path==='/signed-write' ? 'task:write' : 'task:read');
    } else { http_response_code(404); echo '{}'; return; }
    if ($identity===null) { http_response_code(401); echo '{"valid":false}'; return; }
    // Read-only acceptance marker, no real business mutation or account data.
    echo json_encode(['valid'=>true,'subject'=>$identity->subject()]);
} catch (SoSecurity\Exception\SecurityException $e) {
    http_response_code(503); echo json_encode(['valid'=>false,'reason'=>$e->reason()]);
}
