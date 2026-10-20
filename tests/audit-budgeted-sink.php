<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\BudgetedSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\NamespacedStore;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\StorageException;

$directory=privateDirectory();
try {
    $clock=new TestClock();$events=[];$store=new FileStore($directory,'audit-volume',$clock);
    $writer=static function(array $record)use(&$events):void{$events[]=$record;};
    $first=new BudgetedSink($store,'example-site',2,60,$writer,$clock);
    $second=new BudgetedSink(new FileStore($directory,'audit-volume',$clock),'example-site',2,60,$writer,$clock);
    $auditA=new AuditLogger($first,str_repeat('A',32));$auditB=new AuditLogger($second,str_repeat('A',32));
    Check::same(2,$first->inspect()->remaining());
    Check::same(true,$second->inspect()->allowed());
    Check::throws(ConfigurationException::class,static function()use($first):void{
        $first(['time'=>1,'event'=>'login.failed','scope'=>'tenant','subject'=>null,'context'=>[],'password'=>'private']);
    });
    Check::same(0,count($events));
    $auditA->record('login.failed','tenant',"actor\0one",['allowed'=>false,'status'=>401]);
    Check::same(1,$second->inspect()->remaining());
    $auditB->record('csrf.failed','tenant','actor-two',['allowed'=>false]);
    Check::same(false,$first->inspect()->allowed());
    Check::same(0,$first->inspect()->remaining());
    Check::same(60,$first->inspect()->retryAfter());
    Check::same(2,count($events));
    Check::same(hash_hmac('sha256',"actor\0one",str_repeat('A',32)),$events[0]['subject']);
    Check::throws(SecurityException::class,static function()use($auditA):void{$auditA->record('login.failed','tenant','actor-three');});
    Check::same(0,$first->inspect()->remaining());
    Check::same(2,count($events));
    $other=new AuditLogger(new BudgetedSink($store,'second-site',1,60,$writer,$clock),str_repeat('A',32));
    $other->record('login.failed','tenant','other-actor');Check::same(3,count($events));
    $clock->time+=60;
    Check::same(2,$first->inspect()->remaining());
    $auditB->record('login.failed','tenant','after-window');Check::same(4,count($events));
    Check::same(1,$first->inspect()->remaining());
    foreach([new MemoryStore($clock),new NamespacedStore(new MemoryStore($clock),'unsafe')] as $unsafe){
        Check::throws(ConfigurationException::class,static function()use($unsafe,$writer,$clock):void{new BudgetedSink($unsafe,'example-site',2,60,$writer,$clock);});
    }
    Check::throws(ConfigurationException::class,static function()use($store,$writer,$clock):void{new BudgetedSink($store,'example-site',0,60,$writer,$clock);});
    $private='SYNTHETIC-PRIVATE-WRITER-VALUE';
    $failing=new BudgetedSink($store,'failing-site',1,60,static function()use($private):void{throw new RuntimeException('local writer failure');},$clock);
    $safeExport=var_export($failing,true);Check::same(false,strpos($safeExport,$private)!==false);
    Check::same(false,strpos($safeExport,$directory)!==false);
    Check::throws(ConfigurationException::class,static function()use($failing):void{serialize($failing);});
    $failingAudit=new AuditLogger($failing,str_repeat('A',32));
    Check::throws(RuntimeException::class,static function()use($failingAudit):void{$failingAudit->record('audit.fail','tenant','actor');});
    Check::same(0,$failing->inspect()->remaining());
    Check::throws(SecurityException::class,static function()use($failingAudit):void{$failingAudit->record('audit.fail','tenant','actor');});
    $broken=new class implements AtomicStore {
        public function transact(string $key,callable $callback) { throw new StorageException('private test fault','storage.io'); }
    };
    $unavailable=new BudgetedSink($broken,'unavailable-site',1,60,$writer,$clock);
    Check::throws(StorageException::class,static function()use($unavailable):void{$unavailable->inspect();});
    Check::same(4,count($events));
    Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
    echo 'PASS budgeted audit sink: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; shared cap, cross-instance state, strict record shape and fail-closed writer\n";
} finally { cleanDirectory($directory); }
