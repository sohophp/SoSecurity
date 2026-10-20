<?php
declare(strict_types=1);
require __DIR__.'/view-support.php';
snapshotCase(false,static function(InboxTestConnection $pdo,PDO $observer,string $root):void{
    list($sql,$files,$composite,$state,$scratch,$put)=viewSources($pdo,$root);$a=str_repeat('a',64).'.json';$b=str_repeat('b',64).'.json';$missing=str_repeat('f',64).'.json';
    $secret="owned-file-view-secret\0\xff";$put($a,$secret);$put($b,'');$before=$files->digest();$requested=$a;$selectors=['actor'=>&$requested,'empty'=>$b,'missing'=>$missing];
    $c=$files->capture($selectors);$requested=$b;Check::same($before,$c->digest());Check::same($secret,$c->file('actor'));Check::same('',$c->file('empty'));Check::same(null,$c->file('missing'));
    Check::same(true,$c->matches($files));Check::same(true,$c->same($files->capture(['actor'=>$a,'empty'=>$b,'missing'=>$missing])));
    $put($a,'changed-after-capture');Check::same($secret,$c->file('actor'));Check::same(false,$c->same($files->capture(['actor'=>$a,'empty'=>$b,'missing'=>$missing])));
    foreach([var_export($c,true),print_r($c,true),json_encode($c)] as $out){Check::same(false,strpos($out,'owned-file-view-secret')!==false);Check::same(false,strpos($out,$state)!==false);}
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($c):void{serialize($c);});
    $class=SoSecurity\Account\FileStateCapture::class;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($class):void{unserialize('O:'.strlen($class).':"'.$class.'":0:{}');});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($c):void{$c->unknown='edit';});Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($c):void{$c->file('unknown');});
    foreach([[],array_fill_keys(['a','b','c','d','e'],$a),['bad'=>'../'.$a],['bad'=>'lock-0'],['bad'=>str_repeat('g',64).'.json'],['bad'=>new stdClass()]] as $bad){
        $queries=$pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($files,$bad):void{$files->capture($bad);});Check::same($queries,$pdo->queries);Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));
    }
    $store=new SoSecurity\Storage\FileStore($state,'view-store');$store->transact('session',static function():SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(['value'=>"real\0session"],0,true);});
    $name=hash('sha256',"view-store\0session").'.json';$raw=file_get_contents($state.'/'.$name);Check::same($raw,$files->capture(['session'=>$name])->file('session'));
    $large="\0".str_repeat('x',65534)."\0";$put($a,$large);$c=$files->capture(['a'=>$a,'b'=>$a,'c'=>$a,'d'=>$a]);Check::same($large,$c->file('d'));Check::same($files->digest(),$c->digest());
    $put($b,str_repeat('x',65537));snapshotReason('account.snapshot_corrupt',static function()use($files,$a):void{$files->capture(['only'=>$a]);});
    Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));Check::same('8M',ini_get('memory_limit'));Check::same(true,memory_get_peak_usage(false)<8388608);
});
echo 'PASS same-read physical capture: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; hashed raw bytes, empty/missing/NUL, actual FileStore, bounded selectors and aggregate capture, immutable values, exports and unselected corruption\n";
