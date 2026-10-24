<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\CallbackPolicy;
use SoSecurity\Authorization\Decision;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\DependencyException;

$actor=new Account('tenant','alice','1',true,['reader']);$current=$actor;$offline=false;
$source=new CallbackIdentityProvider(static function(){return null;},static function()use(&$current,&$offline){
    if($offline){throw new RuntimeException('PRIVATE-SOURCE');}return $current;
});
$resource=new Resource('tenant','document','one','1');
$mode=$argv[1] ?? 'projection';
if($mode==='projection'){
    foreach(['policy','audit','identity'] as $stage){
        $name='title';$fields=[&$name];
        $mutate=static function()use(&$name):void{$name='secret';};
        $identities=$stage==='identity'?new CallbackIdentityProvider(static function(){return null;},static function()use($actor,$mutate){$mutate();return $actor;}):$source;
        $policy=new CallbackPolicy(static function()use($stage,$mutate){if($stage==='policy'){$mutate();}return Decision::allow(['title']);});
        $audit=$stage==='audit'?new AuditLogger(static function()use($mutate):void{$mutate();},str_repeat('K',32)):null;
        $authorizer=new Authorizer($identities,$policy,$audit);
        Check::same(['title'=>'public'],$authorizer->project('tenant',$actor,'read',$resource,['title'=>'public','secret'=>'PRIVATE'], $fields));
        Check::same('secret',$name);
    }
}else{
    $policy=new CallbackPolicy(static function(){return Decision::allow(['title']);});
    foreach(['disabled','roles','version','missing','offline','same'] as $change){
        $current=$actor;$offline=false;$events=0;
        $audit=new AuditLogger(static function()use(&$current,&$offline,&$events,$change,$actor):void{
            ++$events;
            if($change==='disabled'){$current=new Account('tenant','alice','1',false,['reader']);}
            if($change==='roles'){$current=new Account('tenant','alice','1',true,[]);}
            if($change==='version'){$current=new Account('tenant','alice','2',true,['reader']);}
            if($change==='missing'){$current=null;}
            if($change==='offline'){$offline=true;}
        },str_repeat('K',32));
        $authorizer=new Authorizer($source,$policy,$audit);
        if($change==='offline'){
            try{$authorizer->decide('tenant',$actor,'read',$resource);throw new LogicException('Expected source failure');}
            catch(DependencyException $e){Check::same('authorization.unavailable',$e->reason());Check::same(null,$e->getPrevious());}
        }else{Check::same($change==='same',$authorizer->decide('tenant',$actor,'read',$resource)->allowed());}
        Check::same(1,$events);
    }
}
echo 'PASS authorization callback '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
