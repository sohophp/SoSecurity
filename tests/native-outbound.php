<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
if (getenv('SOSECURITY_TEST_NATIVE_HTTP') !== '1') { echo "NOT RUN native outbound: use isolated network namespace runner\n"; exit(0); }
use SoSecurity\Http\Outbound\Policy;
use SoSecurity\Http\Outbound\Client;
use SoSecurity\Http\RequestException;
use SoSecurity\Exception\ValidationException;

$options=['hosts'=>['api.example.com','cdn.example.com','rebind.example.com','wrong.example.com','127.0.0.1','v6.example.com','dns-slow.example.com'], 'response_bytes'=>65536];
$client=new Client(new Policy($options));
$r=$client->request('GET','https://api.example.com/ok');
Check::same(200,$r->status()); Check::same('8.8.8.8',$r->peer()); Check::same('bounded-ok',$r->body());
Check::same('', $client->request('HEAD','https://api.example.com/ok')->body());
$r=$client->request('GET','https://api.example.com/redirect',['Authorization'=>'TEST-ONLY-AUTH','X-Test'=>'private']);
Check::same('1.1.1.1',$r->peer()); Check::same('credentials-not-forwarded',$r->body());
Check::throws(ValidationException::class,function () use ($client) { $client->request('GET','https://api.example.com/private'); });
Check::throws(ValidationException::class,function () use ($client) { $client->request('GET','https://rebind.example.com/start'); });
Check::throws(RequestException::class,function () use ($client) { $client->request('GET','https://api.example.com/loop'); });
foreach (['/large'=>'http.response_limit','/gzip'=>'http.response_limit','/headers'=>'http.header_limit','/folded'=>'http.headers'] as $path=>$reason) {
    try { $client->request('GET','https://api.example.com'.$path); throw new RuntimeException('Native limit passed'); }
    catch (RequestException $e) { Check::same($reason,$e->reason()); }
}
Check::throws(RequestException::class,function () use ($client) { $client->request('GET','https://wrong.example.com/ok'); });
Check::throws(RequestException::class,function () use ($client) { $client->request('POST','https://api.example.com/redirect',[], '{}'); });
Check::same('POST:{}',$client->request('POST','https://api.example.com/echo',['Content-Type'=>'application/json'],'{}')->body());
$r=$client->request('GET','https://api.example.com/cookie'); Check::same('no-cookie',$client->request('GET','https://api.example.com/cookie-check')->body());
$start=microtime(true);
try { (new Client(new Policy($options+['budget_ms'=>150])))->request('GET','https://api.example.com/slow'); throw new RuntimeException('Slow request passed'); }
catch (RequestException $e) { Check::same('http.timeout',$e->reason()); }
Check::same(true,microtime(true)-$start < 1);
$start=microtime(true);
try { (new Client(new Policy($options+['budget_ms'=>150])))->request('GET','https://dns-slow.example.com/ok'); throw new RuntimeException('Slow DNS passed'); }
catch (RequestException $e) { Check::same('http.timeout',$e->reason()); }
Check::same(true,microtime(true)-$start < 1);
Check::throws(RequestException::class,function () {
    (new SoSecurity\Http\Outbound\CurlTransport())->send(SoSecurity\Http\Uri::parse('https://127.0.0.1/'), '8.8.8.8','GET',[],'',new SoSecurity\Support\Deadline(1000),1024,1024);
});
$r=$client->request('GET','https://v6.example.com/ok'); Check::same('2001:4860:4860::8888',$r->peer());
echo 'PHP '.PHP_VERSION.': '.Check::$assertions." native pinned/TLS/DoH/redirect/budget assertions passed\n";
