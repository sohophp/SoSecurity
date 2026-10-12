<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Http\Outbound\Policy;
use SoSecurity\Http\Outbound\PublicAddress;
use SoSecurity\Http\Outbound\Client;
use SoSecurity\Http\Outbound\Resolver;
use SoSecurity\Http\Outbound\Transport;
use SoSecurity\Http\Outbound\Response;
use SoSecurity\Http\Outbound\DohResolver;
use SoSecurity\Http\Uri;
use SoSecurity\Http\RequestException;
use SoSecurity\Support\Deadline;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\ConfigurationException;

final class TestResolver implements Resolver
{
    public $calls = 0; public $answers;
    public function __construct(array $answers = ['8.8.8.8']) { $this->answers = $answers; }
    public function resolve(string $host, Deadline $deadline): array { ++$this->calls; return $this->answers; }
}
final class TestTransport implements Transport
{
    public $requests = []; private $callback;
    public function __construct(callable $callback) { $this->callback = $callback; }
    public function send(Uri $uri, string $pin, string $method, array $headers, string $body, Deadline $deadline, int $maximumBody, int $maximumHeaders): Response
    {
        $this->requests[] = [$uri->url(),$pin,$method,$headers,$body,$maximumBody,$maximumHeaders];
        return ($this->callback)($uri,$pin,$method,$headers,$body,$deadline,$maximumBody,$maximumHeaders);
    }
}
foreach (['8.8.8.8','1.1.1.1','192.169.120.162','2001:4860:4860::8888','2606:4700:4700::1111'] as $ip) { Check::same(true, PublicAddress::allows($ip)); }
foreach (['127.0.0.1','10.0.0.1','0.0.0.0','100.64.0.1','169.254.169.254','172.16.1.1','192.168.1.1', '192.0.0.9','192.0.2.1','198.18.1.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255',
    '::','::1','::ffff:8.8.8.8','::ffff:127.0.0.1','64:ff9b::a00:1','fc00::1','fe80::1','ff02::1','2001:db8::1','2002:7f00:1::','2001::1','3fff::1','3ffe::1','invalid'] as $ip) { Check::same(false, PublicAddress::allows($ip)); }
$policy = new Policy(['hosts'=>['api.example.com','cdn.example.com']]);
$resolver = new TestResolver(); $transport = new TestTransport(function ($u,$pin) { return new Response(200, [], 'ok', $pin); });
$client = new Client($policy,$resolver,$transport);
Check::same('ok', $client->request('GET','https://api.example.com/a')->body()); Check::same(1,$resolver->calls); Check::same('8.8.8.8',$transport->requests[0][1]);
foreach (['https://evil.example.com/', 'http://api.example.com/', 'https://api.example.com:8443/', 'https://api.example.com.evil/', 'file:///etc/passwd'] as $url) {
    Check::throws(ValidationException::class, function () use ($client,$url) { $client->request('GET',$url); });
}
foreach ([['Host'=>'evil'],['Forwarded'=>'for=127.0.0.1'],['Cookie'=>'SESSION=secret'],['X'=>'ok', 'x'=>'dup'],['X'=>"value\r\nInjected:1"]] as $headers) {
    Check::throws(ValidationException::class, function () use ($client,$headers) { $client->request('GET','https://api.example.com/',$headers); });
}
Check::same(1, count($transport->requests));
$private = new TestResolver(['8.8.8.8','127.0.0.1']);
Check::throws(ValidationException::class, function () use ($policy,$private,$transport) { (new Client($policy,$private,$transport))->request('GET','https://api.example.com/'); });
Check::same(1,count($transport->requests));
$transport = new TestTransport(function ($u,$pin,$method,$headers) {
    if ($u->hostName()==='api.example.com') { return new Response(302,['location'=>['https://cdn.example.com/end']], 'a', $pin); }
    Check::same([], $headers); return new Response(200, [], 'b', $pin);
});
$resolver = new TestResolver(); Check::same('b', (new Client($policy,$resolver,$transport))->request('GET','https://api.example.com/start',['Authorization'=>'SECRET'])->body());
Check::same(2,$resolver->calls); Check::same('SECRET',$transport->requests[0][3]['authorization']);
$transport = new TestTransport(function ($u,$pin) { return new Response(302,['location'=>['https://evil.example.com/']], '',$pin); });
Check::throws(ValidationException::class,function () use ($policy,$transport) { (new Client($policy,new TestResolver(),$transport))->request('GET','https://api.example.com/'); }); Check::same(1,count($transport->requests));
$rebind = new class implements Resolver { private $calls=0; public function resolve(string $host,Deadline $d): array { return ++$this->calls===1 ? ['8.8.8.8'] : ['10.0.0.1']; } };
$transport = new TestTransport(function ($u,$pin) { return new Response(302,['location'=>['/next']], '',$pin); });
Check::throws(ValidationException::class,function () use ($policy,$transport,$rebind) { (new Client($policy,$rebind,$transport))->request('GET','https://api.example.com/'); }); Check::same(1,count($transport->requests));
$transport = new TestTransport(function ($u,$pin) { return new Response(302,['location'=>['/same']], '',$pin); });
Check::throws(RequestException::class,function () use ($policy,$transport) { (new Client($policy,new TestResolver(),$transport))->request('GET','https://api.example.com/same'); });
$transport = new TestTransport(function ($u,$pin) { return new Response(302,['location'=>['/next']], '',$pin); });
Check::throws(RequestException::class,function () use ($transport) { (new Client(new Policy(['hosts'=>['api.example.com'],'redirects'=>0]),new TestResolver(),$transport))->request('GET','https://api.example.com/'); });
Check::throws(RequestException::class,function () use ($policy,$transport) { (new Client($policy,new TestResolver(),$transport))->request('POST','https://api.example.com/',[], '{}'); });
$transport = new TestTransport(function ($u,$pin) { return new Response(200,[], 'oversized', $pin); });
Check::throws(RequestException::class,function () use ($transport) { (new Client(new Policy(['hosts'=>['api.example.com'],'response_bytes'=>2]),new TestResolver(),$transport))->request('GET','https://api.example.com/'); });
$transport = new TestTransport(function ($u,$pin) { return new Response(200,[], 'ok', '127.0.0.1'); });
Check::throws(RequestException::class,function () use ($policy,$transport) { (new Client($policy,new TestResolver(),$transport))->request('GET','https://api.example.com/'); });
$slow = new class implements Resolver { public function resolve(string $host,Deadline $d): array { usleep(30000); return ['8.8.8.8']; } };
Check::throws(RequestException::class,function () use ($slow,$transport) { (new Client(new Policy(['hosts'=>['api.example.com'],'budget_ms'=>10]),$slow,$transport))->request('GET','https://api.example.com/'); });
foreach ([[], ['hosts'=>['*']], ['hosts'=>['localhost']], ['hosts'=>['api.example.com'],'budget_ms'=>null], ['hosts'=>['api.example.com'],'ports'=>['443']], ['hosts'=>['api.example.com'],'allow_http'=>'yes']] as $bad) { Check::throws(ConfigurationException::class,function () use ($bad) { new Policy($bad); }); }
$hosts=['api.example.com']; $frozen = new Policy(['hosts'=>&$hosts]); $hosts[]='evil.example.com'; Check::same(['api.example.com'],$frozen->options()['hosts']);
$transport = new TestTransport(function ($u,$pin) { return new Response(200,[], 'factory', $pin); });
$factory=SoSecurity\Security::fromArray(['site'=>'a','outbound'=>['hosts'=>['api.example.com'],'resolver'=>'dns','transport'=>'wire']],['dns'=>new TestResolver(),'wire'=>$transport]);
Check::same('factory',$factory->outbound()->request('GET','https://api.example.com/')->body());
Check::throws(ConfigurationException::class,function () { SoSecurity\Security::fromArray(['site'=>'a'])->outbound(); });
$dohTransport = new TestTransport(function ($u,$pin) {
    parse_str(parse_url($u->url(),PHP_URL_QUERY),$query); $type=(int)$query['type'];
    $answer=[['name'=>'api.example.com.','type'=>5,'data'=>'cdn.example.com.'],['name'=>'cdn.example.com.','type'=>$type,'data'=>$type===1?'8.8.8.8':'2001:4860:4860::8888']];
    return new Response(200,[],json_encode(['Status'=>0,'Question'=>[['name'=>'api.example.com.','type'=>$type]],'Answer'=>$answer]),$pin);
});
Check::same(['8.8.8.8','2001:4860:4860::8888'],(new DohResolver($dohTransport))->resolve('api.example.com',new Deadline(1000)));
Check::same(2,count($dohTransport->requests));
$badDns = new TestTransport(function ($u,$pin) { return new Response(200,[],json_encode(['Status'=>0,'Question'=>[['name'=>[],'type'=>1]]]),$pin); });
Check::throws(RequestException::class,function () use ($badDns) { (new DohResolver($badDns))->resolve('api.example.com',new Deadline(1000)); });
$forged = new TestTransport(function ($u,$pin) { return new Response(200,['x'=>[str_repeat('a',1024)]],'ok',$pin,0); });
Check::throws(RequestException::class,function () use ($forged) { (new Client(new Policy(['hosts'=>['api.example.com'],'header_bytes'=>256]),new TestResolver(),$forged))->request('GET','https://api.example.com/'); });
Check::same('manual',array_column($factory->diagnose(),null,'check')['outbound.transport']['status']);
Check::same('manual',array_column($factory->diagnose(),null,'check')['outbound.network']['status']);
Check::throws(ConfigurationException::class,function () { new DohResolver(null,'file:///etc/passwd'); });
require dirname(__DIR__).'/examples/outbound.php';
Check::same('factory',SoSecurity\Examples\requestStatus($factory->outbound(),'https://api.example.com/')->body());
echo 'PHP ' . PHP_VERSION . ': ' . Check::$assertions . " outbound policy/adapter assertions passed\n";
