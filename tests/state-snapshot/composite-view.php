<?php
declare(strict_types=1);
require __DIR__.'/view-support.php';$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $root):void{
    list($sql,$files,$composite,$state,$scratch,$put)=viewSources($pdo,$root);$a=str_repeat('a',64).'.json';$put($a,"session\0first");snapshotInsert($pdo,'tenant',1,'','owned-private-view-password');snapshotInsert($pdo,'tenant',2,'',null,'second');
    $before=$composite->digest();$requested=$a;$id=1;$selectors=viewSelections();$selectors['physical']['session']=&$requested;$selectors['sql']['actor']['key']['id']=&$id;
    $pdo->beforeStatement=static function(string $q)use(&$requested,&$id):void{if(strpos($q,'__sw_valid')!==false){$requested=str_repeat('b',64).'.json';$id=2;}};
    try{$c=$composite->capture($selectors);}finally{$pdo->beforeStatement=null;}
    Check::same($before,$c->digest());Check::same(true,$c->matches($composite));Check::same(['tag'=>'owned','password'=>'owned-private-view-password'],$c->part('sql')->row('actor'));Check::same("session\0first",$c->part('physical')->file('session'));
    Check::same(true,$c->part('sql')->matches($sql));Check::same(true,$c->part('physical')->matches($files));
    $put($a,"session\0later");Check::same("session\0first",$c->part('physical')->file('session'));Check::same(false,$before===$composite->digest());
    foreach([var_export($c,true),print_r($c,true),json_encode($c)] as $out){Check::same(false,strpos($out,'owned-private-view-password')!==false);Check::same(false,strpos($out,$state)!==false);}
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($c):void{serialize($c);});$class=SoSecurity\Account\CompositeStateCapture::class;
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($class):void{unserialize('O:'.strlen($class).':"'.$class.'":0:{}');});
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($c):void{$c->part('missing');});
    foreach([[],['missing'=>[]],['sql'=>['actor'=>['table'=>'snapshot_test','key'=>['id'=>1],'columns'=>['tag']]]],['physical'=>['session'=>'../bad']]] as $bad){$queries=$pdo->queries;Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($composite,$bad):void{$composite->capture($bad);});Check::same($queries,$pdo->queries);Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));}
    // First physical scan observes the old file; the SQL part then changes it.
    // The second complete scan must refuse instead of returning a mixed view.
    $changed=false;$pdo->beforeStatement=static function(string $q)use($put,$a,&$changed):void{if(!$changed&&strpos($q,'__sw_valid')!==false){$changed=true;$put($a,"session\0raced");}};
    try{snapshotReason('account.snapshot_changed',static function()use($composite):void{$composite->capture(viewSelections());});}finally{$pdo->beforeStatement=null;}
    Check::same(true,$changed);$fresh=$composite->capture(viewSelections());Check::same($composite->digest(),$fresh->digest());Check::same("session\0raced",$fresh->part('physical')->file('session'));
    // Even an unselected arbitrary snapshot callback is prohibited in this phase.
    $plugin=new class($pdo) implements SoSecurity\Account\StateSnapshot{private $pdo;public $calls=0;public function __construct(PDO $pdo){$this->pdo=$pdo;}public function connection():PDO{return $this->pdo;}public function fingerprint():string{return str_repeat('a',64);}public function digest():string{++$this->calls;return str_repeat('b',64);}};
    $unsafe=new SoSecurity\Account\CompositeStateSnapshot($pdo,['sql'=>$sql,'plugin'=>$plugin]);$queries=$pdo->queries;
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($unsafe):void{$unsafe->capture(['sql'=>['actor'=>viewRow()]]);});Check::same(0,$plugin->calls);Check::same($queries,$pdo->queries);
    Check::same([],array_values(array_diff(scandir($scratch),['.','..'])));Check::same(true,memory_get_peak_usage(false)<8388608);
});
echo 'PASS complete composite capture: '.Check::$assertions.' assertions '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; exact full digest, immutable selector references, two complete passes, cross-source mutation refusal and concrete sources before any callbacks\n";
