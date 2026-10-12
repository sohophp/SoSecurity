<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Http\Uri;
use SoSecurity\Http\Redirects;
use SoSecurity\Http\Cors;
use SoSecurity\Http\PermissionsPolicy;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\ConfigurationException;

$uri = Uri::parse('HTTPS://Example.COM:443/a/../dir/item?q=a%20b');
Check::same('https://example.com/dir/item?q=a%20b', $uri->url());
Check::same('https://example.com/next?x=1', $uri->resolve('../next?x=1')->url());
Check::same('https://cdn.example/a', $uri->resolve('//cdn.example/a')->url());
Check::same('https://example.com/dir/item?only=query', $uri->resolve('?only=query')->url());
Check::same('https://[2001:4860:4860::8888]/', Uri::parse('https://[2001:4860:4860::8888]:443')->url());
foreach (['file:///tmp/a', 'gopher://example.com/', 'https://user:pass@example.com/', 'https://example.com\\@evil/',
    "https://example.com/\r\nX:1", 'https://example.com/%0a', 'https://example.com/%5c', 'https://example.com/%xx',
    'https://example.com:0/', 'https://example.com:0443/', 'https://example.com:65536/', 'https://example.com./',
    'https://127.1/', 'https://0177.0.0.1/', 'https://2130706433/', 'https://0x7f000001/', 'https://0x7f.0.0.1/',
    'https://[fe80::1%25eth0]/', 'https://域名.example/', 'https://example.com/#fragment'] as $bad) {
    Check::throws(ValidationException::class, function () use ($bad) { Uri::parse($bad); });
}
Check::throws(ValidationException::class, function () { Uri::originValue('https://example.com/a/..'); });
$redirects = new Redirects('https://shop.example', ['https://checkout.example:8443']);
Check::same('https://shop.example/account?x=1#tab', $redirects->target('/account?x=1#tab'));
Check::same(true, $redirects->allows('https://checkout.example:8443/pay'));
foreach (['//evil.example/x', 'javascript:alert(1)', 'https://shop.example.evil/x', 'http://shop.example/x', '/%0d%0aLocation:x', 'account'] as $bad) { Check::same(false, $redirects->allows($bad)); }
Check::same('https://shop.example/', $redirects->target('/../'));
$cors = new Cors(['https://client.example'], ['GET','POST'], ['content-type','x-csrf-token'], true, 300, ['retry-after']);
$actual = $cors->evaluate('POST', 'https://client.example', null, null, 'Accept-Encoding');
Check::same(true, $actual->allowed()); Check::same('true', $actual->headers()['Access-Control-Allow-Credentials']);
Check::same('accept-encoding, origin', $actual->headers()['Vary']);
Check::same('*',$cors->evaluate('GET','https://client.example',null,null,'Accept-Encoding, *')->headers()['Vary']); Check::same('retry-after', $actual->headers()['Access-Control-Expose-Headers']);
$preflight = $cors->evaluate('OPTIONS', 'https://client.example', 'POST', 'Content-Type, X-CSRF-Token');
Check::same(204, $preflight->status()); Check::same('https://client.example', $preflight->headers()['Access-Control-Allow-Origin']);
Check::same('origin, access-control-request-method, access-control-request-headers', $preflight->headers()['Vary']);
Check::same(false, $cors->evaluate('OPTIONS', 'https://client.example', 'DELETE')->allowed());
Check::same(false, $cors->evaluate('OPTIONS', 'https://client.example', 'POST', 'x-secret')->allowed());
Check::same(false, $cors->evaluate('OPTIONS', 'https://client.example', 'POST', "content-type\r\nX:1")->allowed());
Check::same(false, $cors->evaluate('GET', 'null')->allowed()); Check::same(false, $cors->evaluate('GET', 'https://client.example/')->allowed());
Check::same(false, $cors->evaluate('GET', 'https://client.example.evil')->allowed());
Check::same(true, $cors->evaluate('GET', null)->allowed()); Check::same(false, $cors->evaluate('OPTIONS', null, 'POST')->allowed());
Check::throws(ConfigurationException::class, function () { new Cors(['*'], ['GET'], [], true); });
Check::throws(ConfigurationException::class, function () { new Cors(['https://client.example/path']); });
Check::throws(ConfigurationException::class, function () { new Cors(['*','https://client.example']); });
Check::throws(ConfigurationException::class, function () { new Cors(['*'], ['TRACE']); });
Check::throws(ConfigurationException::class, function () { new Cors(['*'], ['GET'], ['*']); });
Check::same('*', (new Cors(['*']))->evaluate('GET', 'https://any.example')->headers()['Access-Control-Allow-Origin']);
Check::same('camera=(), geolocation=(self "https://maps.example")', PermissionsPolicy::build(['camera'=>[], 'geolocation'=>['self','https://maps.example']]));
Check::same('fullscreen=*', PermissionsPolicy::build(['fullscreen'=>['*']]));
Check::throws(ConfigurationException::class, function () { PermissionsPolicy::build(['camera'=>['https://host.example/path']]); });
Check::throws(ConfigurationException::class, function () { PermissionsPolicy::build(["camera\r\nX"=>[]]); });
Check::same('camera=()', SoSecurity\Http\SecurityHeaders::build(null, true, null, ['camera'=>[]])['Permissions-Policy']);
foreach (['url'=>['https://example.com/a?x=1#tab','javascript:alert(1)'], 'ip'=>['2001:db8::1','127.1']] as $format=>$values) {
    $validator = new SoSecurity\Validation\Validator(['v'=>['type'=>'string','format'=>$format]]);
    Check::same(true, $validator->validate(['v'=>$values[0]])->valid()); Check::same(false, $validator->validate(['v'=>$values[1]])->valid());
}
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " HTTP policy assertions passed\n";
