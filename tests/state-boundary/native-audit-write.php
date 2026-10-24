<?php
declare(strict_types=1);
use SoSecurity\Support\Deadline;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
$mode=$argv[4]??'normal';$record=['time'=>$clock->time,'event'=>'authorization.allowed','scope'=>'tenant','subject'=>null,'context'=>['allowed'=>true]];
$inspect=static function()use($witness):array{return $witness->inspect(static function():bool{return true;});};$count=static function()use($pdo):int{return (int)$pdo->query('SELECT COUNT(*) FROM sosecurity_audit_records')->fetchColumn();};
$before=$inspect();$writer=null;$deadline=new Deadline(10000);
Check::same(null,$boundary->run('owned.audit.prepare',static function():void{throw new RuntimeException('Denied append executed');},static function()use($auditSink,$record,$deadline,&$writer):bool{$writer=$auditSink->prepareState($record,4,$deadline);return false;},null,$deadline));Check::same(0,$count());Check::same($before,$inspect());
if($mode==='physical'){$boundary->run('owned.audit.fill_other',static function()use($otherAuditSink,$auditSink,$record):void{for($i=0;$i<3;++$i){$otherAuditSink($record);}$auditSink($record);});$before=$inspect();$deadline=new Deadline(10000);Check::throws(SecurityException::class,static function()use($boundary,$auditSink,$record,$deadline):void{$boundary->run('owned.audit.full',static function():void{throw new RuntimeException('Full source admitted');},static function()use($auditSink,$record,$deadline):bool{$auditSink->prepareState($record,4,$deadline);return true;},null,$deadline);});Check::same($before,$inspect());Check::same(4,$count());echo 'PASS native audit physical capacity '.Check::$assertions.PHP_EOL;return;}
$deadline=new Deadline($mode==='budget'?1000:10000);$writer=null;$before=$inspect();
$run=static function()use($boundary,$auditSink,$record,$deadline,&$writer,$mode,$clock):void{
 $boundary->run('owned.audit.write',static function()use(&$writer,$mode,$auditSink,$record):void{if($mode==='changed'){$auditSink($record);}$writer();Check::throws(ConfigurationException::class,$writer);},static function()use($auditSink,$record,$deadline,&$writer,$mode,$clock):bool{$writer=$auditSink->prepareState($record,4,$deadline);if(in_array($mode,['budget','sink-budget'],true)){usleep(1100000);}if($mode==='clock'){--$clock->time;}$record['event']='mutated.event';return true;},null,$deadline);
};
if(in_array($mode,['budget','sink-budget','clock','changed'],true)){
 Check::throws(StorageException::class,$run);Check::same($mode==='changed'?1:0,$count());
 if(in_array($mode,['budget','sink-budget'],true)){Check::same($before,$inspect());}else{Check::same('pending',$inspect()['status']);}
 echo 'PASS native audit '.$mode.' '.Check::$assertions.PHP_EOL;return;
}
$run();Check::same(1,$count());Check::same('authorization.allowed',json_decode($pdo->query('SELECT record FROM sosecurity_audit_records')->fetchColumn(),true)['event']);Check::same($source->digest(),$inspect()['digest']);
$boundary->run('owned.audit.fill',static function()use($auditSink,$record):void{$auditSink($record);$auditSink($record);});$before=$inspect();$deadline=new Deadline(10000);Check::throws(SecurityException::class,static function()use($boundary,$auditSink,$record,$deadline):void{$boundary->run('owned.audit.capacity',static function():void{throw new RuntimeException('Capacity denied callback executed');},static function()use($auditSink,$record,$deadline):bool{$auditSink->prepareState($record,4,$deadline);return true;},null,$deadline);});Check::same($before,$inspect());Check::same(3,$count());
$clock->time+=3601;$deadline=new Deadline(10000);$writer=null;$boundary->run('owned.audit.prune',static function()use(&$writer):void{$writer();},static function()use($auditSink,$record,$deadline,&$writer):bool{$writer=$auditSink->prepareState($record,4,$deadline);return true;},null,$deadline);Check::same(1,$count());Check::same('4',(string)$pdo->query("SELECT next_sequence FROM sosecurity_audit_roots WHERE next_sequence>0")->fetchColumn());Check::same($source->digest(),$inspect()['digest']);
echo 'PASS native audit prepared write '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
