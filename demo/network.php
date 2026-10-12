<?php
declare(strict_types=1);
namespace SoSecurityDemo;

use SoSecurity\Http\Outbound\Client;
use SoSecurity\Http\Outbound\Policy;
use SoSecurity\Http\Outbound\Resolver;
use SoSecurity\Http\Outbound\Transport;
use SoSecurity\Http\Outbound\Response;
use SoSecurity\Http\Uri;
use SoSecurity\Support\Deadline;

/** Fixed test adapters only; no hostname, transport option or route comes from user input. */
final class NetworkSamples
{
    public static function run(string $scenario): array
    {
        $resolver = new class($scenario) implements Resolver {
            private $scenario; public $calls = 0;
            public function __construct(string $scenario) { $this->scenario=$scenario; }
            public function resolve(string $host, Deadline $deadline): array { ++$this->calls; return $this->scenario==='rebind' && $this->calls>1 ? ['10.0.0.1'] : ['8.8.8.8']; }
        };
        $transport = new class($scenario) implements Transport {
            private $scenario; public $calls = 0;
            public function __construct(string $scenario) { $this->scenario=$scenario; }
            public function send(Uri $uri,string $pin,string $method,array $headers,string $body,Deadline $deadline,int $maximumBody,int $maximumHeaders): Response {
                ++$this->calls;
                if ($this->scenario==='redirect_private') { return new Response(302,['location'=>['https://127.0.0.1/']], '',$pin); }
                if ($this->scenario==='rebind') { return new Response(302,['location'=>['/next']], '',$pin); }
                if ($this->scenario==='peer') { return new Response(200,[], 'test','127.0.0.1'); }
                return new Response(200,[],str_repeat('x',64),$pin);
            }
        };
        $client=new Client(new Policy(['hosts'=>['api.example.com','127.0.0.1'],'response_bytes'=>16]),$resolver,$transport);
        $response=$client->request('GET',$scenario==='private'?'https://127.0.0.1/':'https://api.example.com/');
        return ['status'=>$response->status(),'requests'=>$transport->calls,'message'=>'固定隔离测试样例；这不是外部网络请求。'];
    }
}
