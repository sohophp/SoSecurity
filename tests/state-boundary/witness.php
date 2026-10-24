<?php
declare(strict_types=1);
require __DIR__.'/support.php';
function ownedSnapshotBudget():bool{return true;}
function typedWitness(PDO $pdo,string $dir,SoSecurity\Account\StateSnapshot $source):SoSecurity\Account\LocalStateWitness
{
    return new SoSecurity\Account\LocalStateWitness($pdo,$dir.'/authority','owned-site','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('k',32)]),$source,static function($h)use($dir):bool{return snapshotPersist($h,$dir.'/authority');},30000,1);
}
final class OwnedMutableSnapshot implements SoSecurity\Account\StateSnapshot
{
    private $source;
    public $version;
    public $calls=0;
    public function __construct(SoSecurity\Account\StateSnapshot $source){$this->source=$source;$this->version=hash('sha256','owned initial coverage');}
    public function connection():PDO{return $this->source->connection();}
    public function fingerprint():string{return $this->version;}
    public function digest():string{++$this->calls;return $this->source->digest();}
}
$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $dir):void{
    snapshotInsert($pdo,'tenant',1,"a\0b",'owned-old-password');mkdir($dir.'/authority',0700);$source=snapshotSource($pdo);$queries=$pdo->queries;$w=typedWitness($pdo,$dir,$source);Check::same($queries,$pdo->queries);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($pdo,$observer,$dir):void{typedWitness($pdo,$dir,snapshotSource($observer));});
    $w->initialize($source->digest());$initial=$w->inspect('ownedSnapshotBudget');Check::same('current',$initial['status']);
    $value=$w->work(static function()use($pdo):string{$pdo->exec("UPDATE snapshot_test SET password='owned-new-password'");return 'owned-success';},'ownedSnapshotBudget');Check::same('owned-success',$value);
    $current=$w->inspect('ownedSnapshotBudget');Check::same('current',$current['status']);Check::same($source->digest(),$current['digest']);Check::same(false,$initial['digest']===$current['digest']);
    $pdo->exec("UPDATE snapshot_test SET password='owned-old-password'");$ran=false;snapshotReason('account.witness_stale',static function()use($w,&$ran):void{$w->work(static function()use(&$ran):void{$ran=true;},'ownedSnapshotBudget');});Check::same(false,$ran);Check::same($current,$w->inspect('ownedSnapshotBudget'));
    $pdo->exec("UPDATE snapshot_test SET password='owned-new-password'");$different=typedWitness($pdo,$dir,snapshotSource($pdo,32,1000,['scope'=>'tenant']));snapshotReason('account.witness_missing',static function()use($different):void{$different->work(static function():void{},'ownedSnapshotBudget');});
});
snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $dir):void{
    snapshotInsert($pdo,'tenant',1);mkdir($dir.'/authority',0700);$source=snapshotSource($pdo);$mutable=new OwnedMutableSnapshot($source);$w=typedWitness($pdo,$dir,$mutable);$w->initialize($source->digest());$before=$w->inspect('ownedSnapshotBudget');$queries=$pdo->queries;$calls=$mutable->calls;$mutable->version=hash('sha256','owned changed coverage');
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($w):void{$w->work(static function():void{},'ownedSnapshotBudget');});Check::same($queries,$pdo->queries);Check::same($calls,$mutable->calls);Check::same($before,$w->inspect('ownedSnapshotBudget'));
});
echo 'PASS typed witness source binding: '.Check::$assertions.' assertions '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; exact PDO and immutable coverage, actual password restore refusal before callback and no implicit policy adoption\n";
