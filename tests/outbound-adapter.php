<?php
declare(strict_types=1);
namespace SoSecurity\Support {
 function hrtime($asNumber=false){return \OutboundAdapterProbe::$time*1000000000;}
 function microtime($asNumber=false){return \OutboundAdapterProbe::$time;}
}
namespace {
require __DIR__.'/bootstrap.php';
use SoSecurity\Http\Outbound as O;
use SoSecurity\Http\RequestException;
use SoSecurity\Http\Uri;
use SoSecurity\Support\Deadline;
final class OutboundAdapterProbe {public static $time=100.0;}
$mode=$argv[1]??'resolver-fault';$calls=0;$dnsCalls=0;$marker='private-adapter-credential';
$resolver=new class($mode,$marker) implements O\Resolver {
 private $mode;private $marker;public function __construct($mode,$marker){$this->mode=$mode;$this->marker=$marker;}
 public function resolve(string $host,Deadline $d):array{if($this->mode==='resolver-fault'){throw new RuntimeException($this->marker);}return ['8.8.8.8'];}
};
$transport=new class($mode,$marker,$calls) implements O\Transport {
 private $mode;private $marker;private $calls;public function __construct($mode,$marker,&$calls){$this->mode=$mode;$this->marker=$marker;$this->calls=&$calls;}
 public function send(Uri $uri,string $pin,string $method,array $headers,string $body,Deadline $d,int $maximumBody,int $maximumHeaders):O\Response{
  ++$this->calls;
  if(in_array($this->mode,['transport-fault','doh-fault'],true)){throw new RuntimeException($this->marker);}
  if($this->mode==='transport-known'){throw new RequestException($this->marker,'http.timeout',new RuntimeException($this->marker));}
  if($this->mode==='transport-unknown'){throw new RequestException($this->marker,$this->marker);}
  if(strpos($this->mode,'doh-')===0){parse_str((string)parse_url($uri->url(),PHP_URL_QUERY),$query);$type=(int)$query['type'];if($this->mode==='doh-late'&&$type===28){OutboundAdapterProbe::$time+=2;}if($this->mode==='doh-first-late'){OutboundAdapterProbe::$time+=2;}
   $data=['Status'=>0,'Question'=>[['name'=>'owned.example','type'=>$type]],'Answer'=>$type===1?[['name'=>'owned.example','type'=>1,'data'=>'8.8.8.8']]:[]];return new O\Response(200,[],json_encode($data),$pin,$this->mode==='doh-headers'?8193:null);
  }return new O\Response(200,[],'ok',$pin);
 }
};
$run=static function()use($mode,$transport,$resolver){return strpos($mode,'doh-')===0?(new O\DohResolver($transport))->resolve('owned.example',new Deadline(1000)):(new O\Client(new O\Policy(['hosts'=>['owned.example']]),$resolver,$transport))->request('GET','https://owned.example/');};
if(in_array($mode,['normal','doh-normal'],true)){$result=$run();Check::same($mode==='normal'?'ok':['8.8.8.8'],$mode==='normal'?$result->body():$result);}
else{$caught=null;try{$run();}catch(Throwable $e){$caught=$e;}Check::same(true,$caught instanceof RequestException);$expected=$mode==='resolver-fault'||$mode==='doh-fault'?'http.dns':(in_array($mode,['doh-late','doh-first-late','transport-known'],true)?'http.timeout':($mode==='doh-headers'?'http.dns':'http.transport'));Check::same($expected,$caught->reason());Check::same(null,$caught->getPrevious());Check::same(false,strpos($caught->getMessage(),$marker)!==false);}
Check::same($mode==='resolver-fault'?0:(in_array($mode,['doh-late','doh-normal'],true)?2:1),$calls);echo 'PASS outbound adapter '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}
