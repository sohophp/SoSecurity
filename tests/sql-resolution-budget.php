<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
class ResolutionBudgetPDO extends PDO {
 public $prepares=0;
 public function prepare($statement,$options=[]):PDOStatement{++$this->prepares;return parent::prepare($statement,$options);}
}
$pdo=new ResolutionBudgetPDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$unit=new SoSecurity\Support\SqlTransaction($pdo,new TestClock(),1000);
$unit->run(static function()use($pdo,$unit):void{
 $before=$pdo->prepares;
 Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($unit):void{
  SoSecurity\Support\SqlSchema::tables($unit,['sosecurity_'.str_repeat('a',128)=>['types'=>['id'=>'int'],'primary'=>['id'],'indexes'=>[]]]);
 });
 Check::same($before,$pdo->prepares);
});
echo 'PASS table resolution identifier budget '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
