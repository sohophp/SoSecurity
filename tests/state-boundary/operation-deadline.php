<?php
declare(strict_types=1);
require __DIR__.'/support.php';
final class DeadlineObservationSource implements SoSecurity\Account\StateSnapshot
{
    private $source;
    public $delay=false;
    public function __construct(SoSecurity\Account\StateSnapshot $source){$this->source=$source;}
    public function connection():PDO{return $this->source->connection();}
    public function fingerprint():string{return $this->source->fingerprint();}
    public function digest():string{if($this->delay){$this->delay=false;usleep(300000);}return $this->source->digest();}
}
$mysql=($argv[1]??'')==='mysql';
foreach(['direct','boundary'] as $entry){snapshotCase($mysql,static function(InboxTestConnection $pdo,PDO $observer,string $dir)use($entry):void{
    snapshotInsert($pdo,'tenant',1);mkdir($dir.'/authority',0700);$source=new DeadlineObservationSource(snapshotSource($pdo));
    $w=new SoSecurity\Account\LocalStateWitness($pdo,$dir.'/authority','owned-site','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('k',32)]),$source,static function($h)use($dir):bool{return snapshotPersist($h,$dir.'/authority');},30000,1);
    $allow=static function():bool{return true;};$w->initialize($source->digest());$before=$w->inspect($allow);$ran=false;$budget=new SoSecurity\Support\Deadline(250);
    $effect=static function()use(&$ran):void{$ran=true;};$admission=static function()use($source):bool{$source->delay=true;return true;};
    snapshotReason('account.operation_timeout',static function()use($entry,$w,$allow,$effect,$admission,$budget):void{
        if($entry==='direct'){$w->work($effect,$allow,null,$admission,null,$budget);}
        else{(new SoSecurity\Account\StateBoundary($w,$allow))->run('owned.deadline',$effect,$admission,null,$budget);}
    });
    Check::same(false,$ran);Check::same($before,$w->inspect($allow));
    // A new operation remains usable after a proven pre-write refusal.
    Check::same('owned-ok',$w->work(static function():string{return 'owned-ok';},$allow,null,null,null,new SoSecurity\Support\Deadline(1000)));
    Check::same('current',$w->inspect($allow)['status']);
});}
echo 'PASS pre-write operation deadline: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
