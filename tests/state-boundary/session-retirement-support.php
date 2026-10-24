<?php
declare(strict_types=1);
require_once __DIR__.'/installation-support.php';
function sessionRetirementOld(EntryEnvironment $x):array
{
    $token=$x->login()->credential()->token();$remember=$x->remember->issue('tenant','user',$token,'Owned pre-recovery device');Check::same(true,$remember instanceof SoSecurity\Auth\RememberCredential);$pending=$x->auth->password('tenant','owned-pending-browser','owned@example.test',$x->e->password);Check::same('mfa_required',$pending->status());
    $account=$x->boundary->run('owned.old_identity',static function()use($x){return $x->provider->find('tenant','user');});$key=SoSecurity\Support\Guard::key('auth-pending','tenant','owned-pending-browser');$raw=file_get_contents($x->e->directory.'/factors/'.$x->store->snapshotFile($key));$value=json_decode($raw,true)['value'];return ['token'=>$token,'remember'=>$remember->token(),'challenge'=>$pending->challenge(),'account'=>$account,'factor'=>$value['factor'],'epoch'=>$value['epoch']];
}
function sessionRetirementSetup(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control,?callable $persist=null):array
{
    permissionPolicy($x)->accountConnection($x->boundary,$x->e->accounts,new SoSecurity\Account\Policy(),'address','address_version');list($next,$accounts,$manifest)=credentialSetup($x,$op,$control);$service=credentialService($x,$op);$en=$service->prepare($next,$accounts,$manifest,'user','Owned session retirement','witnessBudget');Check::same(true,$service->confirm($next,$accounts,$manifest,'user',$en->selector(),$en->password(),credentialCode($en,$x),'witnessBudget'));$plan=SoSecurity\Account\StateCredentialInstallation::prepare(...array_merge(installationArgs($x,$op,$next,$accounts,$persist),[$manifest,'user',$en->selector(),'witnessBudget',$x->sessions,$x->store]));return [$next,$accounts,$plan,$en];
}
/** Native token readers on copied bytes; identity and factor bindings deliberately remain valid. */
function sessionRetirementProbe(EntryEnvironment $x,array $old,bool $expected):void
{
    $dir=privateDirectory();try{
        foreach(glob($x->e->directory.'/factors/*.json') as $file){copy($file,$dir.'/'.basename($file));chmod($dir.'/'.basename($file),0600);}
        $account=$old['account'];$provider=new class($account) implements SoSecurity\Auth\IdentityProvider {private $a;public function __construct($a){$this->a=$a;}public function authenticate(string $scope,string $id,string $password):?SoSecurity\Auth\Account{return $this->a;}public function find(string $scope,string $subject):?SoSecurity\Auth\Account{return $this->a;}};
        $factor=new class($old['factor']) implements SoSecurity\Auth\SecondFactor {private $b;public $calls=0;public function __construct(string $b){$this->b=$b;}public function binding(string $scope,string $subject):?string{return $this->b;}public function verify(string $scope,string $subject,string $expected,$proof):?string{++$this->calls;return $expected===$this->b?'totp':null;}};
        $store=new SoSecurity\Storage\FileStore($dir,'entry-sessions',$x->e->clock,5000);$sessions=new SoSecurity\Auth\SessionRegistry($store,$provider,$factor,$x->e->clock,1800,28800,16);$auth=new SoSecurity\Auth\AuthenticationFlow($store,$provider,$sessions,static function():bool{return true;},$factor,$x->e->clock,300,10,5);$remember=new SoSecurity\Auth\RememberedLogin($store,$provider,$sessions,$x->e->keys,static function():bool{return true;},$factor,$x->e->clock,2592000,8,300,5);
        Check::same($expected,$sessions->verify('tenant','user',$old['token']) instanceof SoSecurity\Auth\VerifiedSession);Check::same($expected?'authenticated':'invalid',$remember->resume('tenant',$old['remember'])->status());$result=$auth->secondFactor('tenant','owned-pending-browser',$old['challenge'],['type'=>'totp','code'=>'123456']);Check::same($expected?'authenticated':'denied',$result->status());Check::same($expected?1:0,$factor->calls);
    }finally{cleanDirectory($dir);}
}
function sessionRetirementAssert(EntryEnvironment $x,SoSecurity\Account\StateCredentialInstallation $plan,array $old):void
{
    $m=$plan->manifest();Check::same(isset($m['retirement'])?5:3,$m['format']);$raw=file_get_contents($x->e->directory.'/factors/'.$m['session']['reference']['file']);Check::same($m['session']['after'],$raw);$value=json_decode($raw,true)['value'];Check::same([],$value['sessions']);Check::same([],$value['remember']);Check::same(false,$old['epoch']===$value['epoch']);sessionRetirementProbe($x,$old,false);
}
