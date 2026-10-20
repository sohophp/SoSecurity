<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Audit\AuditLogger;
use SoSecurity\Exception\ConfigurationException;

$events=[];$key=str_repeat('K',32);
$audit=new AuditLogger(static function(array $event)use(&$events):void{$events[]=$event;},$key);
$binary="actor\0suffix";
$audit->record('login.failed','tenant',$binary,['allowed'=>false,'status'=>401,'password'=>'private-value']);
Check::same(1,count($events));
Check::same(hash_hmac('sha256',$binary,$key),$events[0]['subject']);
Check::same(false,strpos(json_encode($events),'private-value')!==false);
Check::same(['allowed'=>false,'status'=>401],$events[0]['context']);
$maximum=str_repeat('x',1024);
$audit->record('login.failed','tenant',$maximum);
Check::same(hash_hmac('sha256',$maximum,$key),$events[1]['subject']);
foreach([$maximum.'x',"\0".$maximum,str_repeat('y',1048576)] as $tooLarge){
    Check::throws(ConfigurationException::class,static function()use($audit,$tooLarge):void{$audit->record('login.failed','tenant',$tooLarge);});
    Check::same(2,count($events));
}
Check::throws(ConfigurationException::class,static function()use($audit):void{$audit->record('login.failed','tenant','actor',['allowed'=>'false']);});
Check::same(2,count($events));
$fault=new AuditLogger(static function():void{throw new RuntimeException('local sink failure');},$key);
Check::throws(RuntimeException::class,static function()use($fault):void{$fault->record('login.failed','tenant','actor');});
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
echo 'PASS audit input bound: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; full NUL bytes, 1024-byte boundary, oversized rejection before sink\n";
