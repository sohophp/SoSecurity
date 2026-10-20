<?php
declare(strict_types=1);
$root=getenv('SOSECURITY_TEST_ROOT') ?: dirname(__DIR__);
require $root.'/tests/bootstrap.php';
require $root.'/tests/webhook-inbox-support.php';

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\SqlTransaction;

/** Real canonical deployment DDL; only deliberate dependencies differ between cases. */
final class DependencyEnvironment
{
    public $pdo;
    public $observer;
    public $mysql;
    public $clock;
    private $directory;
    public static function tables(bool $mysql):array
    {
        $tables=[
            'sosecurity_outbox_roots'=>['namespace'],
            'sosecurity_outbox_records'=>['namespace','key_hash'],
            'sosecurity_idempotency_roots'=>['namespace'],
            'sosecurity_idempotency_records'=>['namespace','key_hash'],
            'sosecurity_webhook_inbox'=>['endpoint_key','event_key'],
            'sosecurity_webhook_processing'=>['endpoint_key','receipt_id'],
        ];
        if($mysql){$tables['sosecurity_state']=['namespace_hash','state_key'];}
        return $tables;
    }
    public function __construct(bool $mysql,string $target,string $direction,int $enabled)
    {
        global $root;
        $this->mysql=$mysql;$this->clock=new TestClock();
        if($mysql){$dsn='mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4';}
        else{$this->directory=privateDirectory();$dsn='sqlite:'.$this->directory.'/dependencies.sqlite';}
        $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1];if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
        $this->pdo=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
        if(!$mysql){chmod($this->directory.'/dependencies.sqlite',0600);}
        $this->observer=new PDO($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
        $this->enforcement($enabled);
        foreach(array_merge(['dependency_child','dependency_parent','dependency_business'],array_keys(self::tables($mysql))) as $name){$this->pdo->exec('DROP TABLE IF EXISTS '.$name);}
        $this->pdo->exec('CREATE TABLE dependency_business(id INT NOT NULL PRIMARY KEY)'.($mysql?' ENGINE=InnoDB':''));
        $primary=self::tables($mysql)[$target];$names=implode(',',$primary);$definitions=[];
        foreach($primary as $column){$definitions[]=$column.($mysql?' CHAR('.($column==='receipt_id'?32:64).') CHARACTER SET ascii COLLATE ascii_bin NOT NULL':' TEXT NOT NULL');}
        if($direction==='outgoing'){$this->pdo->exec('CREATE TABLE dependency_parent('.implode(',',$definitions).',PRIMARY KEY('.$names.'))'.($mysql?' ENGINE=InnoDB':''));}
        foreach(['webhook','webhook-processing','idempotency','outbox'] as $module){
            $ddl=preg_replace('/^--.*$/m','',file_get_contents($root.'/resources/sql/'.$module.'-'.($mysql?'mysql':'sqlite').'.sql'));
            $this->install($ddl,$target,$direction,$names);
        }
        if($mysql){$this->install(SoSecurity\Storage\MySqlStore::schema(),$target,$direction,$names);}
        if(strpos($direction,'incoming')===0){
            $reference=$direction==='incoming-uppercase'?strtoupper($target):$target;
            $this->pdo->exec('CREATE TABLE dependency_child('.implode(',',$definitions).',FOREIGN KEY('.$names.') REFERENCES '.$reference.'('.$names.') ON DELETE CASCADE ON UPDATE CASCADE)'.($mysql?' ENGINE=InnoDB':''));
        }
    }
    private function install(string $ddl,string $target,string $direction,string $names):void
    {
        foreach(explode(';',$ddl) as $sql){if(trim($sql)===''){continue;}
            if($direction==='outgoing'&&preg_match('/\ACREATE TABLE(?: IF NOT EXISTS)? '.preg_quote($target,'/').'\s*\(/',trim($sql))){
                // Preserve every canonical column/index; append only a real FK constraint.
                $offset=strrpos($sql,')');$sql=substr($sql,0,$offset).', FOREIGN KEY('.$names.') REFERENCES dependency_parent('.$names.') ON DELETE CASCADE ON UPDATE CASCADE'.substr($sql,$offset);
            }
            $this->pdo->exec($sql);
        }
    }
    public function enforcement(int $enabled):void {$this->pdo->exec($this->mysql?'SET SESSION foreign_key_checks='.$enabled:'PRAGMA foreign_keys='.$enabled);}
    public function enabled():int {return (int)$this->pdo->query($this->mysql?'SELECT @@SESSION.foreign_key_checks':'PRAGMA foreign_keys')->fetchColumn();}
    public function rows(bool $observer=false):int {return (int)($observer?$this->observer:$this->pdo)->query('SELECT COUNT(*) FROM dependency_business')->fetchColumn();}
    public function verify(string $target,SqlTransaction $unit):void
    {
        if(strpos($target,'sosecurity_outbox_')===0){SoSecurity\Outbox\Schema::verify($unit);}
        elseif(strpos($target,'sosecurity_idempotency_')===0){SoSecurity\Idempotency\Schema::verify($unit);}
        elseif($target==='sosecurity_webhook_inbox'){SoSecurity\Webhook\InboxSchema::verify($this->pdo,$this->mysql?'mysql':'sqlite',new Deadline(10000));}
        elseif($target==='sosecurity_webhook_processing'){SoSecurity\Webhook\ProcessingSchema::verify($this->pdo,$this->mysql?'mysql':'sqlite',new Deadline(10000));}
        else{new SoSecurity\Storage\MySqlStore($this->pdo,'dependency-test',$this->clock);}
    }
    public function close():void
    {
        try{$this->pdo->exec('ROLLBACK');}catch(Throwable $ignored){}
        $this->enforcement(1);
        if($this->mysql){foreach(array_merge(['dependency_child'],array_keys(self::tables(true)),['dependency_parent','dependency_business']) as $name){$this->pdo->exec('DROP TABLE IF EXISTS '.$name);}}
        else{$this->observer=null;$this->pdo=null;cleanDirectory($this->directory);}
    }
}
function dependencyCase(bool $mysql,string $target,string $direction,int $enabled,callable $work):void
{
    $e=new DependencyEnvironment($mysql,$target,$direction,$enabled);try{$work($e);}finally{$e->close();}
}
$mysql=($argv[1] ?? '')==='mysql';
foreach(DependencyEnvironment::tables($mysql) as $table=>$primary){
    foreach([0,1] as $enabled){foreach(['incoming','outgoing'] as $direction){
        dependencyCase($mysql,$table,$direction,$enabled,static function(DependencyEnvironment $e)use($table,$enabled):void{
            $unit=new SqlTransaction($e->pdo,$e->clock,10000);$calls=0;
            Check::throws(ConfigurationException::class,static function()use($e,$unit,$table,&$calls):void{
                $unit->run(static function()use($e,$unit,$table,&$calls):void{$e->verify($table,$unit);++$calls;$unit->query('INSERT INTO dependency_business VALUES(2)')->closeCursor();});
            });
            Check::same(0,$calls);Check::same(0,$e->rows(true));Check::same(false,$unit->committed());Check::same($enabled,$e->enabled());
            $e->pdo->exec($e->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');$e->pdo->exec('INSERT INTO dependency_business VALUES(1)');
            Check::throws(ConfigurationException::class,static function()use($e,$unit,$table,&$calls):void{
                $unit->enlist(static function()use($e,$unit,$table,&$calls):void{$e->verify($table,$unit);++$calls;$unit->query('INSERT INTO dependency_business VALUES(2)')->closeCursor();});
            });
            Check::same(0,$calls);Check::same(1,$e->rows());Check::same(0,$e->rows(true));Check::same($enabled,$e->enabled());
            $e->pdo->exec('ROLLBACK');Check::same(0,$e->rows(true));
        });
    }}
    dependencyCase($mysql,$table,'none',1,static function(DependencyEnvironment $e)use($table):void{
        $suffix=$e->mysql?' ENGINE=InnoDB':'';
        $e->pdo->exec('CREATE TABLE dependency_parent(id INT NOT NULL PRIMARY KEY)'.$suffix);
        $e->pdo->exec('CREATE TABLE dependency_child(id INT NOT NULL,FOREIGN KEY(id) REFERENCES dependency_parent(id) ON DELETE CASCADE)'.$suffix);
        $e->pdo->exec('INSERT INTO dependency_parent VALUES(1)');$e->pdo->exec('INSERT INTO dependency_child VALUES(1)');
        if(!$e->mysql){$e->pdo->exec('CREATE TEMP TABLE pragma_foreign_key_list("table" TEXT)');}
        $unit=new SqlTransaction($e->pdo,$e->clock,10000);
        $unit->run(static function()use($e,$table,$unit):void{$e->verify($table,$unit);$unit->query('INSERT INTO dependency_business VALUES(1)')->closeCursor();});
        Check::same(1,$e->rows(true));Check::same(true,$unit->committed());Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM dependency_child')->fetchColumn());Check::same(1,$e->enabled());
    });
    if(!$mysql){
        foreach(['incoming-uppercase','main-shadow'] as $mode){dependencyCase(false,$table,$mode==='main-shadow'?'none':$mode,1,static function(DependencyEnvironment $e)use($table,$mode):void{
            $e->pdo->exec('CREATE TEMP TABLE pragma_foreign_key_list("table" TEXT)');
            if($mode==='main-shadow'){$e->pdo->exec('CREATE TABLE pragma_foreign_key_list("table" TEXT)');}
            $unit=new SqlTransaction($e->pdo,$e->clock,10000);
            Check::throws(ConfigurationException::class,static function()use($e,$unit,$table):void{$unit->run(static function()use($e,$unit,$table):void{$e->verify($table,$unit);});});
            Check::same(0,$e->rows(true));Check::same(1,$e->enabled());
        });}
    }
}
// Exercise the originally destructive public operation against real retained business children.
require $root.'/tests/outbox-support.php';
foreach([0,1] as $enabled){outboxCase($mysql,static function(OutboxEnvironment $e)use($enabled):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$e->append($s,$e->message());
    $claim=$s->claim('tenant','orders','worker');Check::same(true,$s->acknowledge('tenant','orders','worker',$claim->token()));
    $e->pdo->exec($e->mysql?'SET SESSION foreign_key_checks='.$enabled:'PRAGMA foreign_keys='.$enabled);
    $type=$e->mysql?'CHAR(64) CHARACTER SET ascii COLLATE ascii_bin':'TEXT';
    $e->pdo->exec('CREATE TABLE dependency_child(namespace '.$type.' NOT NULL,key_hash '.$type.' NOT NULL,FOREIGN KEY(namespace,key_hash) REFERENCES sosecurity_outbox_records(namespace,key_hash) ON DELETE CASCADE)'.($e->mysql?' ENGINE=InnoDB':''));
    try{
        $e->pdo->exec('INSERT INTO dependency_child SELECT namespace,key_hash FROM sosecurity_outbox_records');$e->clock->time+=4;
        $rootBefore=$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);
        Check::throws(ConfigurationException::class,static function()use($s):void{$s->maintain('tenant','orders','admin');});
        Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM dependency_child')->fetchColumn());Check::same(1,$e->count());
        Check::same($rootBefore,$e->pdo->query('SELECT revision,entries,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));
        Check::same($enabled,(int)$e->pdo->query($e->mysql?'SELECT @@SESSION.foreign_key_checks':'PRAGMA foreign_keys')->fetchColumn());
    }finally{$e->pdo->exec('DROP TABLE dependency_child');}
    Check::same(1,$s->maintain('tenant','orders','admin')['purged']);
},new SoSecurity\Outbox\Policy(['message_age'=>3,'recovery_age'=>10,'retention_seconds'=>0]));}
if($mysql){outboxCase(true,static function(OutboxEnvironment $e):void{
    SoSecurity\Storage\MySqlStore::install($e->pdo);$store=new SoSecurity\Storage\MySqlStore($e->pdo,'cached-dependency',$e->clock);
    Check::same(true,$store->transact('key',static function()use($e){return new SoSecurity\Storage\Change(['value'=>1],$e->clock->time+1,true);}));
    $e->pdo->exec('CREATE TABLE dependency_child(namespace_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,state_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,FOREIGN KEY(namespace_hash,state_key) REFERENCES sosecurity_state(namespace_hash,state_key) ON DELETE CASCADE) ENGINE=InnoDB');
    try{
        $e->pdo->exec('INSERT INTO dependency_child SELECT namespace_hash,state_key FROM sosecurity_state');$e->clock->time+=2;$calls=0;
        Check::throws(ConfigurationException::class,static function()use($store):void{$store->prune(10);});
        Check::throws(ConfigurationException::class,static function()use($store,&$calls):void{$store->transact('key',static function()use(&$calls){++$calls;return new SoSecurity\Storage\Change(null,0);});});
        Check::same(0,$calls);Check::same(false,$e->pdo->inTransaction());
        Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM dependency_child')->fetchColumn());Check::same(1,(int)$e->pdo->query('SELECT COUNT(*) FROM sosecurity_state')->fetchColumn());
        Check::throws(ConfigurationException::class,static function()use($e):void{new SoSecurity\Storage\MySqlStore($e->pdo,'cached-dependency',$e->clock);});
        Check::same(1,(int)$e->pdo->query('SELECT @@SESSION.foreign_key_checks')->fetchColumn());
    }finally{$e->pdo->exec('DROP TABLE dependency_child');}
    Check::same(1,$store->prune(10));$e->pdo->exec('DROP TABLE sosecurity_state');
});}
echo 'PASS private SQL schema dependencies: '.Check::$assertions.' assertions on '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION."; incoming/outgoing FKs, enforcement settings, rollback, business child retention, cached stores and main introspection\n";
