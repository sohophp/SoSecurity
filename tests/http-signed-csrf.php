<?php
declare(strict_types=1);
// Private 127.0.0.1-only test router. The two fixed test login bindings do not model production authentication.
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/examples/signed-form.php';
header('Content-Type: application/json'); header('Cache-Control: no-store');
$config=json_decode(file_get_contents(getenv('SOSECURITY_TEST_SIGNED_CSRF_CONFIG')),true,16);
$secure=getenv('SOSECURITY_TEST_SIGNED_CSRF_HTTPS')==='1';
$cookieName=$secure ? '__Host-test-csrf' : 'test-csrf';
$authName=$secure ? '__Host-test-auth' : 'test-auth';
if ($_SERVER['REQUEST_URI']==='/test-login' && $_SERVER['REQUEST_METHOD']==='POST') {
    $user=$_POST['user'] ?? ''; if (!isset($config['users'][$user])) { http_response_code(401); echo '{}'; return; }
    // Issue an opaque test credential defined in the private test setup; no Session start or token storage.
    header('Set-Cookie: '.SoSecurity\Http\Cookie::header($authName,$config['users'][$user]['credential'],'/',$secure,true,'Lax'),false);
    echo '{}'; return;
}
$binding=null;
foreach ($config['users'] as $user) { if (is_string($_COOKIE[$authName] ?? null) && hash_equals($user['credential'],$_COOKIE[$authName])) { $binding=$user['binding']; } }
if ($binding===null) { http_response_code(401); echo '{}'; return; }
$keys=new SoSecurity\Support\HmacKeys('testkey',['testkey'=>hex2bin($config['secret_hex'])]);
$csrf=new SoSecurity\Csrf\SignedTokens($keys,'private-http-test',30);
$path=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
$policy=new SoSecurity\Csrf\RequestPolicy();
if ($_SERVER['REQUEST_METHOD']==='GET' && $path==='/form') {
    $token=SoSecurity\Examples\signedFormToken($csrf,'update',$binding,$_COOKIE[$cookieName] ?? null);
    header('Set-Cookie: '.SoSecurity\Http\Cookie::header($cookieName,$token,'/',$secure,true,'Lax',30),false);
    echo json_encode(['token'=>$token,'session_started'=>session_status()===PHP_SESSION_ACTIVE]); return;
}
if ($path!=='/update') { http_response_code(404); echo '{}'; return; }
if ($_SERVER['REQUEST_METHOD']!=='POST') { http_response_code(405); echo '{}'; return; }
if (!$policy->requiresToken($_SERVER['REQUEST_METHOD'],$path)) {
    // Business endpoint itself permits POST only; policy false is never business authorization.
    http_response_code(405); echo '{}'; return;
}
// Reject conflicting transport sources rather than silently choosing the less trustworthy one.
$form=$_POST['_csrf'] ?? null; $header=$_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
$valid=SoSecurity\Examples\verifySignedForm($csrf,'update',$binding,$_COOKIE[$cookieName] ?? null,$form,$header);
if (!$valid) { http_response_code(403); echo '{"valid":false}'; return; }
echo '{"valid":true,"session_started":false}';
