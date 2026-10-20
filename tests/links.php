<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/link-support.php';
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Link\Links;
use SoSecurity\Link\Policy;
use SoSecurity\Link\Target;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;

foreach (['http://files.example','https://Files.example','https://files.example/','https://files.example:443','https://u:p@files.example','https://files.example/a','https://files.example?x=1','https://files.example#x','//files.example','https://files.example.','https://127.1'] as $origin) {Check::throws(ConfigurationException::class,static function()use($origin){new Policy($origin);});}
Check::same('http://127.0.0.1:8080',(new Policy('http://127.0.0.1:8080',300,86400,32,true))->origin());
foreach ([[0,100,1],[101,100,1],[1,86401,1],[1,100,0],[1,100,65]] as $args){Check::throws(ConfigurationException::class,static function()use($args){new Policy('https://files.example',...$args);});}
$e=new LinkEnvironment();$target=$e->target();$issued=$e->links->issue($target);
Check::same(300,$issued->expiresAt()-$issued->issuedAt());Check::same(false,$issued->oneTime());Check::same($target,$issued->target());
$verified=$e->links->verify($target,$issued->url());Check::same($issued->id(),$verified->id());Check::same($target,$verified->target());Check::same($issued->issuedAt(),$verified->issuedAt());Check::same($issued->expiresAt(),$verified->expiresAt());Check::same(false,$verified->oneTime());
Check::same(true,$e->links->verify($target,$issued->url())!==null);Check::same('https://files.example',$e->links->policy()->origin());
$once=$e->links->issue($target,true);Check::same(null,$e->links->verify($target,$once->url(),'HEAD'));Check::same(null,$e->links->verify($target,$once->url(),'POST'));
Check::same(true,$e->links->verify($target,$once->url())->oneTime());Check::same(null,$e->links->verify($target,$once->url()));
Check::same(['issue',$target->fingerprint(),'POST'],$e->guards[0]);Check::same(1,count($e->links->all($target)));
$post=$e->target('1',['id'=>'a'],'POST');$onePost=$e->links->issue($post,true);Check::same(null,$e->links->verify($post,$onePost->url(),'GET'));Check::same(true,$e->links->verify($post,$onePost->url(),'POST')!==null);Check::same(null,$e->links->verify($post,$onePost->url(),'POST'));

$resource=$target->resource();
foreach (['','relative','//host/a','/a//b','/a/../b','/a/./b','/a?x=1','/a#x','/a b','/a+b','/%61','/%2F','/%5c','/%25','/%252F','/%00','/%FF','/%e4%b8%ad','/'.str_repeat('x',256),'/'.str_repeat('a/',256)] as $path){Check::throws(ConfigurationException::class,static function()use($resource,$path){new Target('document.read',$resource,$path);});}
foreach (['','UPPER','a b',str_repeat('a',65)] as $purpose){Check::throws(ConfigurationException::class,static function()use($resource,$purpose){new Target($purpose,$resource,'/a');});}
foreach (['HEAD','PUT','get','DELETE'] as $method){Check::throws(ConfigurationException::class,static function()use($resource,$method){new Target('document.read',$resource,'/a',[],$method);});}
foreach ([['_ss'=>'x'],['id'=>1],['id'=>true],['id'=>1.0],['id'=>null],['id'=>[]],['id'=>new stdClass()],['id'=>"\xff"],['id'=>"a\nb"],['id'=>str_repeat('a',257)],['a.b'=>'x'],[0=>'x'],array_fill_keys(range('a','z'),str_repeat('a',100))] as $parameters){Check::throws(ConfigurationException::class,static function()use($resource,$parameters){new Target('document.read',$resource,'/a',$parameters);});}
$unicode=new Target('document.read',$resource,'/%E4%B8%AD%E6%96%87',['name'=>'中文 / & +','empty'=>'']);Check::same('/%E4%B8%AD%E6%96%87?empty=&name=%E4%B8%AD%E6%96%87%20%2F%20%26%20%2B',$unicode->relativeUrl());
$value='Original';$parameters=['id'=>&$value];$detached=new Target('document.read',$resource,'/a',$parameters);$value='Changed';Check::same(['id'=>'Original'],$detached->parameters());
Check::same($target->fingerprint(),$e->target('1',['name'=>'PRIVATE PARAMETER','id'=>'a'])->fingerprint());
foreach ([$e->target('2'),$e->target('1',['id'=>'b']),new Target('document.other',$resource,'/documents/view',$target->parameters()),new Target('document.read',new Resource('other','document','a','1',['owner'=>'alice']),'/documents/view',$target->parameters()),new Target('document.read',new Resource('tenant','document','b','1',['owner'=>'alice']),'/documents/view',$target->parameters()),new Target('document.read',new Resource('tenant','document','a','1',['owner'=>'bob']),'/documents/view',$target->parameters()),new Target('document.read',$resource,'/other',$target->parameters()),$post] as $wrong){$calls=$e->store->calls;Check::same(null,$e->links->verify($wrong,$issued->url()));Check::same($calls,$e->store->calls);}
foreach ([$issued->url().'&tracking=x',$issued->url().'&_ss=duplicate',$issued->url().'#fragment',str_replace('https://files.example','http://files.example',$issued->url()),str_replace('https://files.example','https://FILES.example',$issued->url()),str_replace('files.example','other.example',$issued->url()),str_replace('/documents/view','/documents/./view',$issued->url()),str_replace('id=a&name=PRIVATE%20PARAMETER','name=PRIVATE%20PARAMETER&id=a',$issued->url()),str_replace('PRIVATE%20PARAMETER','PRIVATE+PARAMETER',$issued->url()),str_replace('.r.','.o.',$issued->url()),substr($issued->url(),0,-1).'!',str_repeat('x',2049)] as $bad){$calls=$e->store->calls;Check::same(null,$e->links->verify($target,$bad));Check::same($calls,$e->store->calls);}
Check::same(true,$e->links->verify($target,$issued->url())!==null);
$bound=$e->links->issue($target,true,60,'PRIVATE-SESSION-BINDING');Check::same(null,$e->links->verify($target,$bound->url()));Check::same(null,$e->links->verify($target,$bound->url(),'GET','wrong'));Check::same(true,$e->links->verify($target,$bound->url(),'GET','PRIVATE-SESSION-BINDING')!==null);Check::same(null,$e->links->verify($target,$issued->url(),'GET','PRIVATE-SESSION-BINDING'));
Check::throws(ConfigurationException::class,static function()use($e,$target){$e->links->issue($target,false,86401);});Check::throws(ConfigurationException::class,static function()use($e,$target){$e->links->issue($target,false,1,str_repeat('x',1025));});
Check::same(null,$e->service('other-site')->verify($target,$issued->url()));
$e->keys=new HmacKeys('new',['old'=>str_repeat('k',32),'new'=>str_repeat('n',32)]);$rotated=$e->service();Check::same(true,$rotated->verify($target,$issued->url())!==null);$new=$rotated->issue($target);$e->keys=new HmacKeys('new',['new'=>str_repeat('n',32)]);$current=$e->service();Check::same(null,$current->verify($target,$issued->url()));Check::same(true,$current->verify($target,$new->url())!==null);
Check::same(true,$current->revoke($e->target('2'),$new->id()));Check::same(null,$current->verify($target,$new->url()));Check::same(false,$current->revoke($target,$new->id()));Check::same(false,$current->revoke($target,'bad'));
$otherPurpose=new Target('document.other',$resource,'/other');$other=$current->issue($otherPurpose);$current->revokeAll($target);Check::same([], $current->all($target));Check::same(true,$current->verify($otherPurpose,$other->url())!==null);

// Observe expiry while another record keeps the ledger alive; a backwards clock must not revive it.
$e=new LinkEnvironment();$short=$e->links->issue($target,false,10);$long=$e->links->issue($target,false,20);$e->clock->time+=10;
Check::same(null,$e->links->verify($target,$short->url()));Check::same(1,count($e->links->all($target)));--$e->clock->time;
Check::throws(StorageException::class,static function()use($e,$target,$short){$e->links->verify($target,$short->url());});++$e->clock->time;Check::same(true,$e->links->verify($target,$long->url())!==null);
$e->clock->time+=10;Check::same(null,$e->links->verify($target,$long->url()));$e->clock->time-=10;Check::same(null,$e->links->verify($target,$long->url()));
foreach ([false,true] as $once){
    $e=new LinkEnvironment();$link=$e->links->issue($target,$once,10);$e->store->after=static function()use($e){$e->clock->time+=10;};
    Check::throws(SecurityException::class,static function()use($e,$target,$link){$e->links->verify($target,$link->url());});$e->clock->time-=10;Check::same(null,$e->links->verify($target,$link->url()));
}
$e=new LinkEnvironment();$e->store->after=static function()use($e){$e->clock->time+=10;};Check::throws(SecurityException::class,static function()use($e,$target){$e->links->issue($target,false,10);});Check::same([], $e->links->all($target));
$e=new LinkEnvironment();$link=$e->links->issue($target);$e->store->after=static function()use($e){--$e->clock->time;};Check::throws(StorageException::class,static function()use($e,$target,$link){$e->links->verify($target,$link->url());});++$e->clock->time;Check::same(null,$e->links->verify($target,$link->url()));
// Late cleanup is exact: a replacement record for the same ID must survive.
$e=new LinkEnvironment();$link=$e->links->issue($target,false,10);$key=$e->key();$e->store->after=static function()use($e,$key,$link){$e->clock->time+=10;$e->store->states[$key]['seen']=$e->clock->time;$entry=&$e->store->states[$key]['entries'][$link->id()];$entry['digest']=str_repeat('a',64);$entry['issued']=$e->clock->time;$entry['expires']=$e->clock->time+100;};
Check::throws(SecurityException::class,static function()use($e,$target,$link){$e->links->verify($target,$link->url());});Check::same(1,count($e->links->all($target)));Check::same(str_repeat('a',64),$e->store->states[$key]['entries'][$link->id()]['digest']);

$mutations=[static function(&$s){$s['v']=2;},static function(&$s){$s['extra']=1;},static function(&$s){$s['seen']=-1;},static function(&$s){++$s['seen'];},static function(&$s){$s['entries']='wrong';},static function(&$s){$s['entries']['bad']=reset($s['entries']);},static function(&$s){$s['policy']=str_repeat('a',64);}];
foreach (['digest'=>1,'target'=>'bad','issued'=>-1,'expires'=>100000,'one_time'=>1,'key_id'=>'bad.key'] as $field=>$value){$mutations[]=static function(&$s)use($field,$value){$id=key($s['entries']);$s['entries'][$id][$field]=$value;};}
foreach (['issued'=>99999,'expires'=>100301,'one_time'=>true,'key_id'=>'other'] as $field=>$value){$mutations[]=static function(&$s)use($field,$value){$id=key($s['entries']);$s['entries'][$id][$field]=$value;};}
foreach ($mutations as $mutation){$e=new LinkEnvironment();$link=$e->links->issue($target);$mutation($e->store->states[$e->key()]);Check::throws(StorageException::class,static function()use($e,$target,$link){$e->links->verify($target,$link->url());});}
$e=new LinkEnvironment();$link=$e->links->issue($target,true);$e->store->states[$e->key()]['entries'][$link->id()]['one_time']=false;
Check::throws(StorageException::class,static function()use($e,$target,$link){$e->links->verify($target,$link->url());});
foreach([-1,PHP_INT_MAX] as $invalid){$e=new LinkEnvironment();$link=$e->links->issue($target);$e->store->after=static function()use($e,$invalid){$e->clock->time=$invalid;};Check::throws(StorageException::class,static function()use($e,$target,$link){$e->links->verify($target,$link->url());});$e->clock->time=100000;Check::same(null,$e->links->verify($target,$link->url()));}
$e=new LinkEnvironment();$link=$e->links->issue($target);$e->policy=new Policy('https://files.example',301);Check::throws(StorageException::class,static function()use($e,$target,$link){$e->service()->verify($target,$link->url());});
$e=new LinkEnvironment(new Policy('https://files.example',300,86400,64));for($i=0;$i<64;++$i){$e->links->issue($target);}
Check::same(64,count($e->links->all($target)));Check::throws(SecurityException::class,static function()use($e,$target){$e->links->issue($target);});
$raw=json_encode($e->store->states);foreach(['PRIVATE PARAMETER','sl1.','PRIVATE-SESSION-BINDING','https://files.example'] as $secret){Check::same(false,strpos($raw,$secret)!==false);}
$e->links->revokeAll($target);Check::same([], $e->links->all($target));
foreach ([false,1,null,'yes'] as $answer){$e=new LinkEnvironment();$e->guard=$answer;Check::throws(SecurityException::class,static function()use($e,$target){$e->links->issue($target);});Check::same(0,$e->store->calls);}
$e=new LinkEnvironment();$service=new Links($e->store,$e->keys,'test',$e->policy,static function(){throw new RuntimeException('PRIVATE-GUARD-DETAIL');},$e->clock);
try{$service->issue($target);throw new LogicException('Expected request rejection.');}catch(DependencyException $error){Check::same('link.request_unavailable',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}
$e=new LinkEnvironment();$link=$e->links->issue($target);$e->store->before=static function(){throw new StorageException('Unavailable test backend.');};Check::throws(StorageException::class,static function()use($e,$target,$link){$e->links->verify($target,$link->url());});
foreach ([$link,$e->links,$target,$verified] as $object){Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object){serialize($object);});Check::same(false,strpos(print_r($object,true),'sl1.')!==false);}
Check::throws(ConfigurationException::class,static function()use($target){$target->path='/changed';});
Check::throws(ConfigurationException::class,static function()use($link){$link->url='changed';});
Check::throws(ConfigurationException::class,static function()use($verified){$verified->id='changed';});
Check::throws(ConfigurationException::class,static function()use($e){$e->policy->ttl=1;});
foreach ([-1,PHP_INT_MAX] as $invalid){$e=new LinkEnvironment();$e->clock->time=$invalid;Check::throws(StorageException::class,static function()use($e,$target){$e->links->issue($target);});Check::same(0,$e->store->calls);}

$options=['keys'=>'link_keys','request_guard'=>'link_guard','origin'=>'https://files.example'];$services=['link_keys'=>new HmacKeys('test',['test'=>str_repeat('k',32)]),'link_guard'=>static function(){return true;}];
foreach ([null,['keys'=>'link_keys'], $options+['unknown'=>true],array_merge($options,['ttl'=>'300']),array_merge($options,['allow_http'=>1])] as $invalid){Check::throws(ConfigurationException::class,static function()use($invalid){SoSecurity\Security::fromArray(['site'=>'test','signed_links'=>$invalid]);});}
Check::throws(ConfigurationException::class,static function(){SoSecurity\Security::fromArray(['site'=>'test'])->signedLinks();});
Check::throws(ConfigurationException::class,static function()use($options,$services){SoSecurity\Security::fromArray(['site'=>'test','signed_links'=>$options,'storage'=>['driver'=>'memory']],$services)->signedLinks();});
Check::throws(ConfigurationException::class,static function()use($options,$services){SoSecurity\Security::fromArray(['site'=>'test','signed_links'=>$options,'storage'=>['driver'=>'session']],$services)->signedLinks();});
$directory=privateDirectory();try{
    $security=SoSecurity\Security::fromArray(['site'=>'test','signed_links'=>$options,'storage'=>['driver'=>'file','directory'=>$directory]],$services);$links=$security->signedLinks();$link=$links->issue($target,true);Check::same(true,$links->verify($target,$link->url())!==null);Check::same(null,$links->verify($target,$link->url()));
    $diagnostic=json_encode($security->diagnose());Check::same(true,strpos($diagnostic,'signed_links.resource')!==false);Check::same(false,strpos($diagnostic,$directory)!==false);
    Check::throws(ConfigurationException::class,static function()use($directory,$options){SoSecurity\Security::fromArray(['site'=>'test','signed_links'=>$options,'storage'=>['driver'=>'file','directory'=>$directory]])->signedLinks();});
}finally{cleanDirectory($directory);}
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
echo 'PASS signed links: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; canonical fixed-origin target/method/version binding, retained revocation/one-use, key rotation, expiry, retry purity and fail-closed I/O\n";
