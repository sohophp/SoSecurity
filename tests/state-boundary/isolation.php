<?php
declare(strict_types=1);
require __DIR__.'/support.php';
final class UntrustedWitnessSource implements SoSecurity\Account\StateSnapshot
{
    private $pdo;public $calls=0;
    public function __construct(PDO $pdo){$this->pdo=$pdo;}
    public function connection():PDO{++$this->calls;return $this->pdo;}
    public function fingerprint():string{++$this->calls;return str_repeat('a',64);}
    public function digest():string{++$this->calls;return str_repeat('a',64);}
}
function isolationReason(string $reason,callable $operation):void
{
    ++Check::$assertions;try{$operation();}catch(SoSecurity\Exception\ConfigurationException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected exact source isolation refusal.');
}
$mysql=($argv[1]??'')==='mysql';
snapshotCase($mysql,static function(PDO $pdo,PDO $observer,string $directory)use($mysql):void{
    snapshotInsert($pdo,'tenant',1,'owned unchanged state');foreach(['authority','files','scratch'] as $name){mkdir($directory.'/'.$name,0700);}
    $keys=new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('k',32)]);$fake=new UntrustedWitnessSource($pdo);
    isolationReason('configuration.state_witness',static function()use($pdo,$directory,$keys,$fake):void{new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/authority','owned-site','tenant',str_repeat('e',64),$keys,$fake,static function():bool{return true;});});Check::same(0,$fake->calls);
    $sql=snapshotSource($pdo);$files=new SoSecurity\Account\FileStateSnapshot($pdo,'owned-files',$directory.'/files',$directory.'/scratch',10,30000);$source=new SoSecurity\Account\CompositeStateSnapshot($pdo,['sql'=>$sql,'files'=>$files],30000);
    $writes=0;$witness=new SoSecurity\Account\LocalStateWitness($pdo,$directory.'/files','owned-site','tenant',str_repeat('e',64),$keys,$source,static function()use(&$writes):bool{++$writes;return true;},30000);
    isolationReason('configuration.state_independence',static function()use($witness,$source):void{$witness->initialize($source->digest());});Check::same(0,$writes);
    $q=$observer->query('SELECT body FROM snapshot_test');Check::same('owned unchanged state',$q->fetchColumn());$q->closeCursor();
    if(!$mysql){
        $parent=new SoSecurity\Account\LocalStateWitness($pdo,$directory,'owned-site','tenant',str_repeat('e',64),$keys,$sql,static function()use(&$writes):bool{++$writes;return true;},30000);
        isolationReason('configuration.state_independence',static function()use($parent,$sql):void{$parent->initialize($sql->digest());});Check::same(0,$writes);
    }
});
echo 'PASS concrete witness isolation: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; unknown providers refused before callbacks, authority/source overlap refused before persistence, business rows unchanged',PHP_EOL;
