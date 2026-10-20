<?php
declare(strict_types=1);
require __DIR__.'/operations-support.php';
managedCase(static function(ManagedEnvironment $e):void{
    $e->registry->initialize('user');$f=purgeFence($e);$approval=0;$s=normalOperations($e,$f,static function()use(&$approval):bool{++$approval;return true;});$s->initialize();$r=$s->review('disable','user','owned-review');$proof=normalFactor($e);$before=$e->row();
    foreach(['action','subject','expires','seal','stamp','authority'] as $field){$v=$r;if($field==='expires'){$v[$field]-=10;}elseif($field==='action'){$v[$field]='regenerate';}elseif($field==='subject'){$v[$field]='other';}else{$v[$field]=str_repeat('0',64);}$queries=$e->pdo->queries;$calls=$approval;Check::throws(SoSecurity\Exception\SecurityException::class,static function()use($s,$v,$proof):void{$s->execute($v,'owned-tamper',normalProof(),$proof);});Check::same($queries,$e->pdo->queries);Check::same($calls,$approval);}
    foreach([['stamp',new stdClass()],['subject',str_repeat('x',100000)],['issued','100000']] as $case){$v=$r;$v[$case[0]]=$case[1];$queries=$e->pdo->queries;Check::throws(InvalidArgumentException::class,static function()use($s,$v,$proof):void{$s->execute($v,'owned-input',normalProof(),$proof);});Check::same($queries,$e->pdo->queries);}
    Check::same($before,$e->row());Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());
    $f->drain(static function():void{},static function():bool{return true;});$queries=$e->pdo->queries;$calls=$approval;fenceReason('factor.fence_closed',static function()use($s,$r,$proof):void{$s->execute($r,'owned-closed',normalProof(),$proof);});Check::same($queries,$e->pdo->queries);Check::same($calls,$approval);
});
echo 'PASS normal factor input boundaries: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; tampered/oversize/object reviews refused before SQL or approval, closed authority refusal\n";
