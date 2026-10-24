<?php
declare(strict_types=1);
require __DIR__.'/grants-native-support.php';
require dirname(__DIR__,2).'/examples/StateDocumentLinks.php';
use SoSecurity\Account\Example\StateDocuments;
use SoSecurity\Account\Example\StateDocumentLinks;
function nativeLinks(EntryEnvironment $x,?callable $guard=null,?SoSecurity\Link\Policy $policy=null):SoSecurity\Link\Links
{
    return new SoSecurity\Link\Links($x->store,$x->e->keys,'managed-test',$policy??new SoSecurity\Link\Policy('https://links.example.test',300,3600,8),$guard??static function():bool{return true;},$x->e->clock,$x->boundary,permissionPolicy($x),$x->sessions,new SoSecurity\Authorization\Authorizer($x->provider,StateDocumentLinks::policy()));
}
function linkPrepare(string $id='owned',?int $version=null):Closure{return static function(PDO $pdo)use($id,$version):SoSecurity\Link\Target{return StateDocumentLinks::target($pdo,'tenant',$id,$version);};}
function linkIssue(EntryEnvironment $x,SoSecurity\Link\Links $links,string $token,bool $once=true,?int $ttl=null,string $binding=''):SoSecurity\Link\IssuedLink{return $links->issueFor('tenant','user',$token,$x->e->pdo,StateDocuments::definition(),linkPrepare(),$once,$ttl,$binding);}
function linkVerify(EntryEnvironment $x,SoSecurity\Link\Links $links,string $url,string $method='POST',string $binding=''):?SoSecurity\Link\VerifiedLink{return $links->verifyFor('tenant',$x->e->pdo,StateDocuments::definition(),linkPrepare(),$url,$method,$binding);}
function linkOperation(EntryEnvironment $x,array $record,string $entry,?string $actor,SoSecurity\Link\Target $target):void
{
    $m=$record['intent'];Check::same('authorized',$m['kind']);Check::same('links.'.$entry,$m['action']);Check::same(SoSecurity\Account\StateOperation::scope('tenant'),$m['scope']);Check::same($target->fingerprint(),$m['target']);if($actor!==null){Check::same(hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Subject.1','tenant',$actor],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)),$m['actor']);}else{Check::same(false,$m['actor']===hash('sha256',json_encode(['SoSecurity.Account.StateOperation.Subject.1','tenant','user'],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)));}foreach(['permission','policy'] as $f){Check::same(1,preg_match('/\A[a-f0-9]{64}\z/D',$m[$f]));}Check::same(SoSecurity\Account\StateOperation::digestOf($m),$record['intent_digest']);
}
function linkExpected(EntryEnvironment $x,SoSecurity\Link\Links $links,string $entry,?string $actor,?string $token,SoSecurity\Link\Target $target,array $options,string $observed):array
{
    $j=JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE;$keys=$x->e->keys;$policy=hash('sha256','SoSecurity.Link.Native.Policy.1.'.json_encode([permissionPolicy($x)->binding(),StateDocumentLinks::policy()->fingerprint(),$links->policy()->fingerprint(),'managed-test',$keys->currentId(),bin2hex($keys->sign('SoSecurity.Link.Native.Key.1.managed-test'))],$j));$parts=isset($options['url'])?SoSecurity\Link\Encoding::parse($options['url'],$links->policy(),$target):null;$names=array_keys(StateDocuments::definition());sort($names);$request=hash('sha256','SoSecurity.Link.Native.Request.1.'.json_encode(['entry'=>$entry,'actor'=>$actor,'session'=>$token===null?null:SoSecurity\Auth\SessionRegistry::reference($token),'target'=>$target->fingerprint(),'one_time'=>$options['one_time']??null,'ttl'=>$options['ttl']??null,'binding'=>isset($options['binding'])?SoSecurity\Link\Encoding::binding($options['binding']):null,'proof'=>$parts===null?($options['id']??null):$parts['digest'],'tables'=>$names,'observed'=>$observed,'policy'=>$policy],$j));return SoSecurity\Account\StateOperation::link('links.'.$entry,'tenant',$actor,$target->fingerprint(),$request,$policy,$x->e->clock->time)->metadata();
}
