<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Exception\ConfigurationException;
$directory=privateDirectory();$pdo=null;
try {
 $pdo=new PDO('sqlite:'.$directory.'/case.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
 $pdo->exec('CREATE TABLE business(id INTEGER NOT NULL PRIMARY KEY)');
 foreach(['sosecurity_case_probe','SOSECURITY_CASE_PROBE','SoSecurity_Case_Probe'] as $name){
  foreach(['none','main','temp','unrelated'] as $scope){
   foreach([false,true] as $enlist){
    $pdo->exec('CREATE TABLE '.$name.'(id INTEGER NOT NULL PRIMARY KEY,value INTEGER NOT NULL)');
    $pdo->exec('CREATE TABLE other_table(id INTEGER NOT NULL)');
    if($scope!=='none'){$pdo->exec('CREATE '.($scope==='temp'?'TEMP ':'').'TRIGGER owned_case_trigger AFTER INSERT ON '.($scope==='unrelated'?'other_table':$name).' BEGIN INSERT INTO business VALUES(new.id); END');}
    $unit=new SqlTransaction($pdo,new TestClock(),10000);$called=0;$rejected=false;
    if($enlist){$pdo->exec('BEGIN IMMEDIATE');$pdo->exec('INSERT INTO business VALUES(99)');}
    $work=static function()use($pdo,$unit,&$called):void{SqlSchema::table($unit,'sosecurity_case_probe',['id'=>'int','value'=>'int'],['id']);++$called;$unit->query('INSERT INTO sosecurity_case_probe VALUES(1,2)')->closeCursor();};
    try{if($enlist){$unit->enlist($work);}else{$unit->run($work);}}catch(ConfigurationException $error){Check::same('configuration.sql_schema',$error->reason());$rejected=true;}
    $blocked=in_array($scope,['main','temp'],true);
    if($blocked&&!$rejected){echo 'UNEXPECTED_ACCEPT '.json_encode(['table'=>$name,'scope'=>$scope,'enlist'=>$enlist,'effects'=>(int)$pdo->query('SELECT COUNT(*) FROM business WHERE id=1')->fetchColumn()]).PHP_EOL;}
    Check::same($blocked,$rejected);Check::same($blocked?0:1,$called);
    Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM business WHERE id=1')->fetchColumn());
    Check::same($blocked?0:1,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_case_probe')->fetchColumn());
    if($enlist){Check::same(1,(int)$pdo->query('SELECT COUNT(*) FROM business WHERE id=99')->fetchColumn());$pdo->exec('ROLLBACK');Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM business')->fetchColumn());}
    if($scope!=='none'){$pdo->exec('DROP TRIGGER '.($scope==='temp'?'temp.':'main.').'owned_case_trigger');}
    $pdo->exec('DROP TABLE '.$name);$pdo->exec('DROP TABLE other_table');
   }
  }
 }
}finally{if($pdo!==null&&$pdo->inTransaction()){$pdo->rollBack();}$pdo=null;cleanDirectory($directory);}
echo 'PASS SQLite trigger identifier case: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
