<?php
declare(strict_types=1);
require __DIR__.'/permission-support.php';

function grantsEntryConfiguration(callable $build):void
{
    ++Check::$assertions;
    try{$build();}catch(SoSecurity\Exception\ConfigurationException $error){Check::same('configuration.state_boundary',$error->reason());return;}
    throw new RuntimeException('Expected exact grant/session state authority.');
}

managedCase(static function(ManagedEnvironment $e):void{
    $e->pdo->exec("UPDATE account_example SET roles='[\"operator\"]'");
    $earlyLookups=0;$calls=0;$hasher=new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]);
    $provider=new SoSecurity\Auth\PasswordIdentityProvider(
        static function(string $scope,string $address)use($e,&$earlyLookups){++$earlyLookups;$record=$e->accounts->findAddress($scope,new SoSecurity\Account\Address($address));return $record===null?null:$e->accounts->passwordRecord($record);},
        static function(string $scope,string $subject)use($e,&$earlyLookups){++$earlyLookups;$record=$e->accounts->find($scope,$subject);return $record===null?null:$e->accounts->passwordRecord($record);},
        $hasher,$hasher->hash('Owned early grant admission dummy password 49!')
    );
    $raw=new SoSecurity\Storage\FileStore($e->directory.'/factors','entry-sessions',$e->clock);
    $earlySessions=new SoSecurity\Auth\SessionRegistry($raw,$provider,$e->registry->secondFactor(),$e->clock);
    $guard=static function()use(&$calls):bool{++$calls;return true;};
    // Construct an ordinary service before this physical directory becomes protected.
    $late=new SoSecurity\Operation\Grants($raw,$earlySessions,new SoSecurity\Authorization\Authorizer($provider),$guard,null,$e->clock);
    $x=new EntryEnvironment($e);$login=$x->login();$token=$login->credential()->token();$e->clock->time+=60;
    $authorizer=new SoSecurity\Authorization\Authorizer($x->provider,new SoSecurity\Authorization\RolePolicy([
        'account.change'=>['type'=>'account','roles'=>['operator'],'fields'=>[]]
    ]));
    $bound=new SoSecurity\Operation\Grants($x->store,$x->sessions,$authorizer,$guard,null,$e->clock,$x->boundary);
    $intent=new SoSecurity\Operation\Intent('account.change',new SoSecurity\Authorization\Resource('tenant','account','user','1'));
    $before=entryFiles($x);$root=$x->inspect();$lookups=$x->lookups;$reads=$e->reads;$queries=$e->pdo->queries;
    foreach([$late,$bound] as $grants){
        $methods=[
            static function()use($grants,$token,$intent):void{$grants->begin('tenant','user',$token,$intent);},
            static function()use($grants,$token,$intent):void{$grants->confirm('tenant','user',$token,$intent,'oc1.'.str_repeat('a',32).'.'.str_repeat('b',64));},
            static function()use($grants,$token,$intent):void{$grants->consume('tenant','user',$token,$intent,'og1.'.str_repeat('a',32).'.'.str_repeat('b',64));},
            static function()use($grants,$token):void{$grants->revoke('tenant','user',$token,str_repeat('a',32));},
            static function()use($grants,$token):void{$grants->revokeAll('tenant','user',$token);}
        ];
        foreach($methods as $method){witnessReason('account.state_required',$method);}
    }
    Check::same(0,$calls);Check::same(0,$earlyLookups);Check::same($lookups,$x->lookups);Check::same($reads,$e->reads);Check::same($queries,$e->pdo->queries);
    Check::same($before,entryFiles($x));Check::same($root,$x->inspect());

    $wrapped=$x->boundary->protect($x->store);
    foreach([$x->store,clone $x->store,$wrapped,new SoSecurity\Storage\NamespacedStore($x->store,'raw'),new SoSecurity\Storage\NamespacedStore($wrapped,'nested')] as $store){
        grantsEntryConfiguration(static function()use($store,$x,$authorizer,$guard,$e):void{new SoSecurity\Operation\Grants($store,$x->sessions,$authorizer,$guard,null,$e->clock);});
    }
    grantsEntryConfiguration(static function()use($x,$earlySessions,$authorizer,$guard,$e):void{new SoSecurity\Operation\Grants($x->store,$earlySessions,$authorizer,$guard,null,$e->clock,$x->boundary);});
    $unprotected=new SoSecurity\Storage\MemoryStore($e->clock);
    grantsEntryConfiguration(static function()use($unprotected,$x,$authorizer,$guard,$e):void{new SoSecurity\Operation\Grants($unprotected,$x->sessions,$authorizer,$guard,null,$e->clock);});
    grantsEntryConfiguration(static function()use($unprotected,$x,$e):void{new SoSecurity\Auth\AuthenticationFlow($unprotected,$x->provider,$x->sessions,$x->guard,$x->factorAdapter,$e->clock);});
    grantsEntryConfiguration(static function()use($unprotected,$x,$e):void{new SoSecurity\Auth\RememberedLogin($unprotected,$x->provider,$x->sessions,$e->keys,$x->guard,$x->factorAdapter,$e->clock);});
    foreach([new SoSecurity\Storage\NamespacedStore($wrapped,'nested'),new SoSecurity\Storage\NamespacedStore(new SoSecurity\Storage\NamespacedStore($wrapped,'inner'),'outer')] as $store){
        grantsEntryConfiguration(static function()use($store,$x,$e):void{new SoSecurity\Auth\SessionRegistry($store,$x->provider,$x->factorAdapter,$e->clock);});
        grantsEntryConfiguration(static function()use($store,$x,$e):void{new SoSecurity\Auth\AuthenticationFlow($store,$x->provider,$x->sessions,$x->guard,$x->factorAdapter,$e->clock);});
        grantsEntryConfiguration(static function()use($store,$x,$e):void{new SoSecurity\Auth\RememberedLogin($store,$x->provider,$x->sessions,$e->keys,$x->guard,$x->factorAdapter,$e->clock);});
    }
    Check::same(0,$calls);Check::same(0,$earlyLookups);Check::same($lookups,$x->lookups);Check::same($before,entryFiles($x));Check::same($root,$x->inspect());

    $policy=permissionPolicy($x);$permission=new SoSecurity\Account\StatePermission('account.change','tenant','user','user',$token,['operator']);
    $perform=static function(callable $work)use($x,$policy,$permission){return $x->boundary->authorized('account.change','tenant','user',$policy,$permission,$work);};
    $confirmation=$perform(static function()use($bound,$token,$intent){return $bound->begin('tenant','user',$token,$intent);});
    Check::same(true,$confirmation instanceof SoSecurity\Operation\Confirmation);Check::same(1,$calls);Check::same('current',$x->inspect()['status']);
    $parts=explode('.',$confirmation->token());
    Check::same(true,$perform(static function()use($bound,$token,$parts):bool{return $bound->revoke('tenant','user',$token,$parts[1]);}));
    $perform(static function()use($bound,$token):void{$bound->revokeAll('tenant','user',$token);});
    Check::same(3,$calls);Check::same(false,$x->boundary->active());Check::same('current',$x->inspect()['status']);
});
echo 'PASS protected grant and nested-store entries: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; all five grant effects refused before callbacks/session writes, late directory binding and exact session authority, nested protected stores require explicit boundaries, approved operations remain usable',PHP_EOL;
