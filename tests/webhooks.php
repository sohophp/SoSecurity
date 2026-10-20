<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Webhook\Endpoint;
use SoSecurity\Webhook\KeySet;
use SoSecurity\Webhook\Request;
use SoSecurity\Webhook\Verifier;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\StorageException;

function webhookEndpoint(string $protocol='standard-hmac',array $options=[],string $id='test'):Endpoint
{return new Endpoint($id,'tenant','provider-account','https://hooks.example/events',$protocol,$options+($protocol==='github-sha256'?['allow_untimed'=>true]:[]));}
function webhookHeaders(Endpoint $endpoint,string $body,string $key,int $time=100000,string $id='msg_test'):array
{
    $protocol=$endpoint->protocol();if($protocol==='github-sha256'){return ['X-Hub-Signature-256'=>'sha256='.hash_hmac('sha256',$body,$key),'X-GitHub-Delivery'=>'untrusted-delivery','X-GitHub-Event'=>'untrusted-type'];}
    if($protocol==='stripe-v1'){return ['Stripe-Signature'=>'t='.$time.',v1='.hash_hmac('sha256',$time.'.'.$body,$key)];}
    $message=$id.'.'.$time.'.'.$body;$signature=$protocol==='standard-ed25519'?sodium_crypto_sign_detached($message,$key):hash_hmac('sha256',$message,$key,true);
    return ['Webhook-Id'=>$id,'Webhook-Timestamp'=>(string)$time,'Webhook-Signature'=>($protocol==='standard-ed25519'?'v1a,':'v1,').base64_encode($signature)];
}
function webhookVerify(Endpoint $endpoint,string $key,array $headers,string $body='{}',?TestClock $clock=null):?SoSecurity\Webhook\VerifiedWebhook
{
    $keys=new KeySet($endpoint,['test'=>$key]);$verifier=new Verifier($endpoint,static function()use($keys){return $keys;},static function(){return true;},$clock ?? new TestClock());return $verifier->verify(new Request('POST',$endpoint->url(),$body,$headers));
}
foreach([['extra'=>true],['allow_http'=>1],['allow_untimed'=>true],['maximum_body'=>-1],['maximum_body'=>1048577],['tolerance'=>0],['tolerance'=>901],['future_skew'=>-1],['future_skew'=>121],['io_milliseconds'=>0],['io_milliseconds'=>'10']] as $options){Check::throws(ConfigurationException::class,static function()use($options){webhookEndpoint('standard-hmac',$options);});}
Check::throws(ConfigurationException::class,static function(){new Endpoint('test','tenant','provider','https://hooks.example/','github-sha256');});
foreach(['http://hooks.example/','https://hooks.example/#fragment','https://hooks.example:443/','https://user:password@hooks.example/','https://HOOKS.example/'] as $url){Check::throws(ConfigurationException::class,static function()use($url){new Endpoint('test','tenant','provider',$url,'standard-hmac');});}
$limit=12;$options=['maximum_body'=>&$limit];$endpoint=webhookEndpoint('standard-hmac',$options);$limit=99;Check::same(12,$endpoint->maximumBody());$copy=$endpoint->options();$copy['maximum_body']=0;Check::same(12,$endpoint->maximumBody());
foreach([['Webhook-Id'=>'x','webhook-id'=>'x'],['bad.name'=>'value'],['x'=>[]],['x'=>"bad\r\n"],['x'=>str_repeat('x',4097)]] as $headers){Check::throws(ValidationException::class,static function()use($headers){new Request('POST','https://hooks.example/','{}',$headers);});}
Check::throws(ValidationException::class,static function(){new Request('POST','https://hooks.example/',str_repeat('x',1048577),[]);});
foreach(['standard-hmac','stripe-v1','github-sha256','standard-ed25519'] as $protocol){
    if($protocol==='standard-ed25519'&&!extension_loaded('sodium')){Check::throws(DependencyException::class,static function(){new KeySet(webhookEndpoint('standard-ed25519'),['test'=>str_repeat('k',32)]);});if(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required sodium unavailable.');}continue;}
    $endpoint=webhookEndpoint($protocol);$key=str_repeat('k',32);$signing=$key;
    if($protocol==='standard-ed25519'){$pair=sodium_crypto_sign_seed_keypair(str_repeat('s',32));$key=sodium_crypto_sign_publickey($pair);$signing=sodium_crypto_sign_secretkey($pair);}
    $body="{\n\"type\":\"event.changed\",\"value\":\"工具/😀\"}\n";$headers=webhookHeaders($endpoint,$body,$signing);$clock=new TestClock();$keyset=new KeySet($endpoint,['test'=>$key]);$lookups=0;
    $service=new Verifier($endpoint,static function()use($keyset,&$lookups){++$lookups;return $keyset;},static function(){return true;},$clock);
    $request=new Request('POST',$endpoint->url(),$body,$headers);$proof=$service->verify($request);Check::same(true,$proof!==null);Check::same(2,$lookups);Check::same($body,$proof->body());Check::same(hash('sha256',$body),$proof->bodyDigest());Check::same('test',$proof->keyId());Check::same($endpoint->fingerprint(),$proof->endpoint()->fingerprint());
    Check::same($protocol==='github-sha256'?null:100000,$proof->timestamp());Check::same(strpos($protocol,'standard-')===0?'msg_test':null,$proof->messageId());Check::same($protocol==='github-sha256'?null:100301,$proof->expiresAt());
    $before=$lookups;Check::same(null,$service->verify(new Request('GET',$endpoint->url(),$body,$headers)));Check::same($before,$lookups);Check::same(null,$service->verify(new Request('POST',$endpoint->url().'?other',$body,$headers)));Check::same($before,$lookups);
    Check::same(null,$service->verify(new Request('POST',$endpoint->url(),$body.' ',$headers)));Check::same($before+1,$lookups);
    foreach([$request,$keyset,$service,$proof] as $object){Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object){serialize($object);});Check::same(false,strpos(print_r($object,true),$body)!==false);Check::same(false,strpos(print_r($object,true),$signing)!==false);}
    foreach([false,1,null] as $deny){$guarded=new Verifier($endpoint,static function()use($keyset){return $keyset;},static function()use($deny){return $deny;},$clock);Check::throws(SecurityException::class,static function()use($guarded,$request){$guarded->verify($request);});}
    $broken=new Verifier($endpoint,static function(){throw new RuntimeException('PRIVATE-KEY-SOURCE');},static function(){return true;},$clock);try{$broken->verify($request);throw new LogicException('Expected key failure.');}catch(DependencyException $error){Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}
    $wrong=new KeySet(webhookEndpoint($protocol,[],'another'),['test'=>$key]);$broken=new Verifier($endpoint,static function()use($wrong){return $wrong;},static function(){return true;},$clock);Check::throws(DependencyException::class,static function()use($broken,$request){$broken->verify($request);});
    $calls=0;$withdrawn=new Verifier($endpoint,static function()use($keyset,&$calls){return ++$calls===1?$keyset:null;},static function(){return true;},$clock);Check::same(null,$withdrawn->verify($request));Check::same(2,$calls);
    if($protocol==='github-sha256'){
        $headers['X-GitHub-Delivery']='attacker-replaced-id';$headers['X-GitHub-Event']='attacker-replaced-type';$changed=webhookVerify($endpoint,$key,$headers,$body);Check::same(true,$changed!==null);Check::same(null,$changed->messageId());Check::same($proof->bodyDigest(),$changed->bodyDigest());
    }else{
        foreach([-301,-300,-299,0,29,30,31] as $offset){$headers=webhookHeaders($endpoint,$body,$signing,100000+$offset);$result=webhookVerify($endpoint,$key,$headers,$body);Check::same($offset>=-300&&$offset<=30,$result!==null);}
        $lateClock=new TestClock();$late=new Verifier($endpoint,static function()use($lateClock,$keyset){$lateClock->time+=301;return $keyset;},static function(){return true;},$lateClock);Check::same(null,$late->verify($request));
    }
    $backwardClock=new TestClock();$backward=new Verifier($endpoint,static function()use($keyset){return $keyset;},static function()use($backwardClock){--$backwardClock->time;return true;},$backwardClock);Check::throws(StorageException::class,static function()use($backward,$request){$backward->verify($request);});
}
$endpoint=webhookEndpoint();$key=str_repeat('k',32);$headers=webhookHeaders($endpoint,'{}',$key);
foreach(['','01','-1','1e5','9223372036854775808','9999999999999999999'] as $timestamp){$bad=$headers;$bad['Webhook-Timestamp']=$timestamp;Check::same(null,webhookVerify($endpoint,$key,$bad));}
foreach(['','dot.id','id with spaces'] as $id){$bad=$headers;$bad['Webhook-Id']=$id;Check::same(null,webhookVerify($endpoint,$key,$bad));}
foreach(['v1,','v2,'.base64_encode(str_repeat('x',32)),'v1,'.base64_encode(str_repeat('x',31)),str_repeat($headers['Webhook-Signature'].' ',17)] as $signature){$bad=$headers;$bad['Webhook-Signature']=$signature;Check::same(null,webhookVerify($endpoint,$key,$bad));}
$encoded=new KeySet($endpoint,['old'=>str_repeat('o',32),'new'=>$key]);$service=new Verifier($endpoint,static function()use($encoded){return $encoded;},static function(){return true;},new TestClock());$headers['Webhook-Signature']='v1,'.base64_encode(hash_hmac('sha256','msg_test.100000.{}',str_repeat('o',32),true)).' '.$headers['Webhook-Signature'];Check::same('old',$service->verify(new Request('POST',$endpoint->url(),'{}',$headers))->keyId());
$encoded=KeySet::fromEncoded($endpoint,['test'=>'whsec_'.base64_encode($key)]);Check::same(true,$encoded->matches($endpoint));Check::throws(ConfigurationException::class,static function()use($key){KeySet::fromEncoded(webhookEndpoint('stripe-v1'),['test'=>'whsec_'.base64_encode($key)]);});
foreach([[],['bad'=>str_repeat('k',23)],['first'=>$key,'second'=>$key]] as $keys){Check::throws(ConfigurationException::class,static function()use($endpoint,$keys){new KeySet($endpoint,$keys);});}
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
$timedEndpoint=webhookEndpoint('standard-hmac',['io_milliseconds'=>100]);$timedKeys=new KeySet($timedEndpoint,['test'=>str_repeat('k',32)]);$timedRequest=new Request('POST',$timedEndpoint->url(),'{}',webhookHeaders($timedEndpoint,'{}',str_repeat('k',32)));$timedCalls=0;
$timed=new Verifier($timedEndpoint,static function()use($timedKeys,&$timedCalls){++$timedCalls;usleep(150000);return $timedKeys;},static function(){return true;},new TestClock());
Check::throws(StorageException::class,static function()use($timed,$timedRequest){$timed->verify($timedRequest);});Check::same(1,$timedCalls);
$timedCalls=0;$timed=new Verifier($timedEndpoint,static function()use(&$timedCalls){++$timedCalls;return null;},static function(){usleep(150000);return true;},new TestClock());Check::throws(StorageException::class,static function()use($timed,$timedRequest){$timed->verify($timedRequest);});Check::same(0,$timedCalls);
// GitHub's published vector, not a private production secret.
Check::same(true,webhookVerify(webhookEndpoint('github-sha256'),"It's a Secret to Everybody",['X-Hub-Signature-256'=>'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17'],'Hello, World!')!==null);
if(extension_loaded('sodium')){
    // RFC 8032 section 7.1, empty-message Ed25519 primitive; this does not claim an empty signed webhook frame.
    $rfcKey=hex2bin('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    $rfcSignature=hex2bin('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
    Check::same('rfc',(new KeySet(webhookEndpoint('standard-ed25519'),['rfc'=>$rfcKey]))->verify('',[$rfcSignature]));
}
echo 'PASS webhook verification core: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; four fixed profiles, raw bytes, current endpoint keys, signed freshness, GitHub unsigned metadata, rotation, budgets and dependency refusal; isolated synthetic signatures only\n";
