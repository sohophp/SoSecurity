<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$v=json_decode(stream_get_contents(STDIN),true);$directory=$v['directory'];
if(!is_string($directory)||strpos($directory,sys_get_temp_dir().'/sosecurity-test-')!==0||is_link($directory)||!is_file($directory.'/initial-claim-owner')){throw new RuntimeException('Owned initial claim worker required');}
$pdo=new PDO('sqlite:'.$directory.'/outbox.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$clock=new TestClock();
$queue=new SoSecurity\Outbox\SqlOutbox($pdo,'outbox-test',str_repeat('e',64),new SoSecurity\Support\HmacKeys('old',['old'=>str_repeat('o',32)]),static function():bool{return true;},null,$clock,static function():bool{return true;});
echo $queue->claimInitialMessage('tenant','orders',$v['worker'],$v['id'])===null?'0':'1';
