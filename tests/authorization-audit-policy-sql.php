<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/audit-sql-support.php';
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Audit\AuditLogger;
use SoSecurity\Audit\SqlSink;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\CallbackPolicy;
use SoSecurity\Authorization\Decision;
use SoSecurity\Authorization\Resource;
$env=new AuditSqlEnvironment(($argv[1]??'sqlite')==='mysql');
$table='owned_auth_policy_'.bin2hex(random_bytes(8));
try{
 $pdo=$env->pdo;$pdo->exec('CREATE TABLE '.$table.' (id INTEGER NOT NULL PRIMARY KEY, enabled INTEGER NOT NULL, fields VARCHAR(128) NOT NULL)');
 $pdo->exec("INSERT INTO ".$table." VALUES(1,1,'title,body')");
 $actor=new Account('tenant','alice','1',true,['reader']);
 $source=new CallbackIdentityProvider(static function(){return null;},static function()use($actor){return $actor;});
 $policy=new CallbackPolicy(static function()use($pdo,$table):Decision{$row=$pdo->query('SELECT enabled,fields FROM '.$table.' WHERE id=1')->fetch(PDO::FETCH_ASSOC);return (int)$row['enabled']===1?Decision::allow(explode(',',$row['fields'])):Decision::deny();});
 $sink=new SqlSink($pdo,'authorization-policy-test',4,3600,$env->clock);$sink->initialize();$change='disable';$events=0;
 $audit=new AuditLogger(static function(array $record)use($sink,$pdo,$table,&$change,&$events):void{$sink($record);++$events;$pdo->exec('UPDATE '.$table.' SET '.($change==='disable'?'enabled=0':"fields='body'").' WHERE id=1');},str_repeat('K',32));
 $auth=new Authorizer($source,$policy,$audit);$resource=new Resource('tenant','document','one','1');
 Check::same(false,$auth->decide('tenant',$actor,'read',$resource)->allowed());Check::same(1,$env->count());Check::same(1,$events);
 $pdo->exec('UPDATE '.$table.' SET enabled=1 WHERE id=1');$change='fields';
 Check::same(false,$auth->decide('tenant',$actor,'read',$resource,['title'])->allowed());Check::same(2,$env->count());Check::same(2,$events);
 Check::same(false,$pdo->inTransaction());echo 'PASS SQL authorization policy recheck '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
}finally{$env->pdo->exec('DROP TABLE IF EXISTS '.$table);$env->close();}
