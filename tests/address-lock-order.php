<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/address-change-support.php';
$socket=(($argv[1] ?? '')==='mysql'?(getenv('SOSECURITY_TEST_MYSQL_SOCKET') ?: ''):($argv[1] ?? ''));if($socket!==''){if(!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Expected an owned local test database.');}$GLOBALS['registrationMySQLSocket']=$socket;}
changeCase(static function(ChangeEnvironment $t):void{
    $pdo=$t->e->pdo;
    $observe=static function(callable $operation)use($pdo):void{
        $manual=false;$wasActive=false;$index=-1;$groups=[];
        $pdo->afterExec=static function(string $sql)use(&$manual,&$wasActive,&$index,&$groups):void{
            $sql=strtoupper(trim($sql));if($sql==='BEGIN IMMEDIATE'){$manual=true;$wasActive=true;$groups[++$index]=[];}
            elseif(in_array($sql,['COMMIT','ROLLBACK'],true)){$manual=false;$wasActive=false;}
        };
        $pdo->beforeStatement=static function(string $sql)use($pdo,&$manual,&$wasActive,&$index,&$groups):void{
            $active=$manual||$pdo->inTransaction();if(!$active){$wasActive=false;return;}
            if(!$wasActive){$groups[++$index]=[];$wasActive=true;}
            if(preg_match('/FROM (?:main\.)?sosecurity_account_roots WHERE namespace=/', $sql)){$groups[$index][]='ledger';}
            elseif(preg_match('/FROM account_example WHERE /',$sql)){$groups[$index][]='account';}
        };
        try{$operation();}finally{$pdo->beforeStatement=null;$pdo->afterExec=null;}
        $checked=0;foreach($groups as $group){if(in_array('account',$group,true)){++$checked;Check::same('ledger',$group[0]);}}Check::same(true,$checked>0);
    };
    $s=$t->service;$intent=null;
    $observe(static function()use($t,$s,&$intent):void{$intent=$s->proposal($t->subject,'new@example.com',$t->credential->token(),'ip');});
    $grant=$t->approve($intent);
    $observe(static function()use($t,$s,$grant):void{$s->request($t->subject,'new@example.com',$t->credential->token(),$grant,'ip');});
    $d=$t->deliveries();$selector=$d['verify_address_old']->selector();
    foreach(['old','new'] as $side){Check::same(true,$s->confirm($selector,$side,$d['verify_address_'.$side]->notice()->token(),'ip'));}
    $grant=$t->approve($s->completionProposal($t->subject,$selector,$t->credential->token(),'ip'));
    $observe(static function()use($t,$s,$selector,$grant):void{Check::same(true,$s->complete($t->subject,$selector,$t->credential->token(),$grant,'ip'));});
    Check::same('new@example.com',$t->e->account()['address']);
});
echo 'PASS address root-before-account lock order: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."\n";
