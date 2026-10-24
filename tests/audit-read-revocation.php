<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\BudgetedSink;
use SoSecurity\Audit\Diagnostics;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Audit\RecentEvents;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;

final class RevokingAuditStore implements AtomicStore
{
    private $store;public $after;public $calls=0;
    public function __construct(AtomicStore $store){$this->store=$store;}
    public function transact(string $key,callable $callback){
        ++$this->calls;$result=$this->store->transact($key,$callback);
        if($this->after!==null){($this->after)();}return $result;
    }
}
$directory=privateDirectory();
try{
    $clock=new TestClock();$store=new RevokingAuditStore(new FileStore($directory,'revocation',$clock));
    $allowed=true;$checks=0;$authorize=static function()use(&$allowed,&$checks):bool{++$checks;return $allowed;};
    if(($argv[1] ?? '')==='diagnostics'){
        $metrics=new MetricsSink($store,'site',['login.failed'=>'authentication'],['authentication'=>1],10,60,static function(array $record):void{},$clock);
        $budget=new BudgetedSink(new FileStore($directory,'budget',$clock),'site',10,60,$metrics,$clock);
        (new AuditLogger($budget,str_repeat('K',32)))->record('login.failed','tenant','actor');
        $reader=new Diagnostics($metrics,$budget,$authorize);
        $read=static function()use($reader):array{return $reader->inspect();};
    }else{
        $reader=new RecentEvents($store,'site',str_repeat('S',32),2,60,static function(array $record):void{},$authorize,$clock);
        (new AuditLogger($reader,str_repeat('K',32)))->record('login.failed','tenant','actor');
        $read=static function()use($reader):array{return $reader->recent(2);};
    }
    $calls=$store->calls;$allowed=false;
    Check::throws(SecurityException::class,static function()use($read):void{$read();});Check::same($calls,$store->calls);
    $allowed=true;$store->after=static function()use(&$allowed):void{$allowed=false;};
    Check::throws(SecurityException::class,static function()use($read):void{$read();});
    Check::same(false,$allowed);
    $store->after=null;$allowed=true;Check::same(true,count($read())>0);
    echo 'PASS audit read revocation '.($argv[1] ?? 'recent').': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; initial denial skips storage, revocation during IO prevents return\n";
}finally{cleanDirectory($directory);}
