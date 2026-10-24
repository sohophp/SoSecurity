<?php
declare(strict_types=1);
use SoSecurity\Exception\ConfigurationException;
$method=$argv[4]??'idempotency';if(!in_array($method,['idempotency','outbox'],true)){throw new RuntimeException('Select a fixed factory');}
// Only self-created, uninitialized foreign SQLite; factory construction must not admit it as protected state.
Check::throws(ConfigurationException::class,static function()use($sdk,$method):void{$sdk->$method();});
Check::same(0,$idemCalls);Check::same($before,$source->digest());Check::same('0',(string)$foreign->query("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")->fetchColumn());
// A same-PDO service still lacks native preflight and must not appear successfully connected either.
$services['foreign']=$pdo;$same=SoSecurity\Security::fromArray($config,$services,$clock);Check::throws(ConfigurationException::class,static function()use($same,$method):void{$same->$method();});Check::same(0,$idemCalls);Check::same($before,$source->digest());
$ordinaryConfig=['site'=>$config['site'],'idempotency'=>$config['idempotency'],'outbox'=>$config['outbox']];$services['foreign']=$foreign;$ordinary=SoSecurity\Security::fromArray($ordinaryConfig,$services,$clock);Check::same($method==='outbox'?SoSecurity\Outbox\SqlOutbox::class:SoSecurity\Idempotency\SqlExecutor::class,get_class($ordinary->$method()));Check::same(0,$idemCalls);
echo 'PASS protected '.$method.' factory default denial '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
