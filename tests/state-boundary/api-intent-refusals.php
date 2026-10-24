<?php
declare(strict_types=1);
require __DIR__.'/api-intent-support.php';
entryCase(static function(EntryEnvironment $x):void{
    $token=$x->login()->credential()->token();$api=nativeApi($x);$key=$api->issue('tenant','user',$token,'Before denials',['records:read']);$root=$x->inspect();$effects=0;
    foreach([
        ['api.credentials.issue',SoSecurity\Account\StateOperation::credential('api.credentials.all','tenant','user','user',str_repeat('a',64),str_repeat('b',64),$x->e->clock->time)],
        ['api.credentials.issue',SoSecurity\Account\StateOperation::credential('api.credentials.issue','foreign','user','user',str_repeat('a',64),str_repeat('b',64),$x->e->clock->time)],
        ['api.credentials.issue',SoSecurity\Account\StateOperation::internal('api.credentials.issue','tenant')],
        ['owned.non_api',SoSecurity\Account\StateOperation::credential('api.credentials.issue','tenant','user','user',str_repeat('a',64),str_repeat('b',64),$x->e->clock->time)],
    ] as $case){$persists=0;$x->persistHook=static function()use(&$persists):bool{++$persists;return true;};Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($x,$case,&$effects):void{$x->boundary->run($case[0],static function()use(&$effects):void{++$effects;},static function()use($case){return $case[1];});});$x->persistHook=null;Check::same(0,$persists);Check::same($root,$x->inspect());}Check::same(0,$effects);
    // A constructed description cannot substitute for a real native session or host admission.
    nativeApiNoEffect($x,static function()use($api):void{$api->issue('tenant','user','invalid','Forged description',['records:read']);},'api_credentials.denied');$denied=nativeApi($x,static function():bool{return false;});nativeApiNoEffect($x,static function()use($denied,$token):void{$denied->issue('tenant','user',$token,'Rejected host',['records:read']);},'api_credentials.denied');Check::same($root,$x->inspect());
    $at=$x->e->clock->time;$backwards=nativeApi($x,null,static function()use($x):array{--$x->e->clock->time;return ['records:read'];});try{nativeApiNoEffect($x,static function()use($backwards,$key):void{$backwards->authenticate('tenant',$key->token(),'records:read');},'api_credentials.clock');}finally{$x->e->clock->time=$at;}
    $rule=['api.credentials.issue'=>['type'=>'api_credential_owner','roles'=>['operator'],'fields'=>[]]];$r=new SoSecurity\Authorization\RolePolicy($rule);Check::same($r->fingerprint(),(new SoSecurity\Authorization\RolePolicy($rule))->fingerprint());foreach(['roles','fields','owner_attribute','match'] as $key){$changed=$rule;if($key==='roles'){$changed['api.credentials.issue'][$key]=['other'];}elseif($key==='fields'){$changed['api.credentials.issue'][$key]=['digest'];}elseif($key==='owner_attribute'){$changed['api.credentials.issue'][$key]='owner';}else{$changed['api.credentials.issue'][$key]=['realm'=>'other'];}Check::same(false,$r->fingerprint()===(new SoSecurity\Authorization\RolePolicy($changed))->fingerprint());}
});
entryCase(static function(EntryEnvironment $x):void{
    $op=SoSecurity\Account\StateOperation::credential('api.credentials.issue','tenant','user','user',str_repeat('a',64),str_repeat('b',64),$x->e->clock->time);$root=$x->inspect();$effects=0;witnessReason('account.witness_changed',static function()use($x,$op,&$effects):void{$x->boundary->run('api.credentials.issue',static function()use(&$effects):void{++$effects;},static function()use($x,$op){$x->e->pdo->exec("UPDATE account_example SET roles='[\"unregistered-writer\"]'");return $op;});});Check::same(0,$effects);Check::same($root,$x->inspect());
});
echo 'PASS native API intent refusal integrity: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; wrong action/scope/kind and non-API substitution refuse before pending, descriptions grant no session authority, roles/fields/ownership/attributes bind policy, changed source is not adopted\n";
