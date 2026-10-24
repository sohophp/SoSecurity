<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}
$pdo=new PDO('mysql:unix_socket='.$socket.';dbname=sosecurity_test','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$schema=SoSecurity\Storage\MySqlStore::schema();
try{
 foreach(['canonical','primary-prefix','expiry-prefix','expiry-unique','cached-primary-prefix','cached-expiry-prefix','cached-expiry-unique','extra-unique','cached-extra-unique'] as $mode){
  if(isset($argv[1])&&$argv[1]!==$mode){continue;}$sql=$schema;
  if($mode==='primary-prefix'){$sql=str_replace('PRIMARY KEY (namespace_hash, state_key)','PRIMARY KEY (namespace_hash, state_key(1))',$sql);}
  if($mode==='expiry-prefix'){$sql=str_replace('KEY sosecurity_expiry (namespace_hash, expires_at)','KEY sosecurity_expiry (namespace_hash(1), expires_at)',$sql);}
  if($mode==='expiry-unique'){$sql=str_replace('KEY sosecurity_expiry','UNIQUE KEY sosecurity_expiry',$sql);}
  if($mode==='extra-unique'){$sql=str_replace('KEY sosecurity_expiry','UNIQUE KEY unexpected_namespace(namespace_hash), KEY sosecurity_expiry',$sql);}
  $pdo->exec($sql);$rejected=false;
  try{$store=new SoSecurity\Storage\MySqlStore($pdo,'owned-index',new TestClock());}catch(SoSecurity\Exception\ConfigurationException $error){$rejected=true;}
  if(strpos($mode,'cached-')===0){
   if($mode==='cached-extra-unique'){$pdo->exec('ALTER TABLE sosecurity_state ADD UNIQUE KEY unexpected_namespace(namespace_hash)');}
   elseif($mode==='cached-primary-prefix'){$pdo->exec('ALTER TABLE sosecurity_state DROP PRIMARY KEY, ADD PRIMARY KEY(namespace_hash,state_key(1))');}
   elseif($mode==='cached-expiry-prefix'){$pdo->exec('ALTER TABLE sosecurity_state DROP INDEX sosecurity_expiry, ADD KEY sosecurity_expiry(namespace_hash(1),expires_at)');}
   else{$pdo->exec('ALTER TABLE sosecurity_state DROP INDEX sosecurity_expiry, ADD UNIQUE KEY sosecurity_expiry(namespace_hash,expires_at)');}
   $called=false;try{if($mode==='cached-expiry-prefix'){$store->prune(1);}else{$store->transact('owned-cached-key',static function()use(&$called){$called=true;return new SoSecurity\Storage\Change(['owned'=>true],200000,null);});}}catch(SoSecurity\Exception\ConfigurationException $error){$rejected=true;}
   Check::same(false,$called);Check::same(0,(int)$pdo->query('SELECT COUNT(*) FROM sosecurity_state')->fetchColumn());
  }
  if((in_array($mode,['primary-prefix','extra-unique'],true)&&!$rejected)||$mode==='canonical'){
   $keys=[];$pair=null;for($i=0;$i<100;++$i){$key='owned-key-'.$i;$prefix=substr(hash('sha256',$key),0,1);if(isset($keys[$prefix])){$pair=[$keys[$prefix],$key];break;}$keys[$prefix]=$key;}
   Check::same(true,$pair!==null);$store->transact($pair[0],static function(){return new SoSecurity\Storage\Change(['owned'=>'first-key'],200000,null);});
   $seen=$store->transact($pair[1],static function($value){return new SoSecurity\Storage\Change($value,200000,$value);});if($mode==='canonical'){Check::same(null,$seen);$first=$store->transact($pair[0],static function($value){return new SoSecurity\Storage\Change($value,200000,$value);});Check::same(['owned'=>'first-key'],$first);}else{echo 'CROSS_KEY_VALUE '.json_encode($seen).PHP_EOL;}
  }
  Check::same($mode!=='canonical',$rejected);$pdo->exec('DROP TABLE sosecurity_state');
 }
}finally{$pdo->exec('DROP TABLE IF EXISTS sosecurity_state');}
echo 'PASS exact private store indexes '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
