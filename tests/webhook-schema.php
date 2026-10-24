<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Deadline;
use SoSecurity\Webhook\InboxSchema;
use SoSecurity\Webhook\ProcessingSchema;

class WebhookMetadataStatement extends InboxTestStatement
{
    public function fetchAll($mode=null,$className=null,$constructorArgs=null,...$extra):array
    {
        $rows=parent::fetchAll(...func_get_args());$sql=$this->queryString;
        if(strpos($sql,'table_info')!==false||strpos($sql,'information_schema.COLUMNS')!==false){$limit=65;$bytes=128;}
        elseif(strpos($sql,'index_list')!==false){$limit=129;$bytes=256;}
        elseif(strpos($sql,'index_info')!==false||strpos($sql,'information_schema.STATISTICS')!==false){$limit=5;$bytes=64;}
        else{return $rows;}
        if(count($rows)>$limit){echo 'UNBOUNDED_METADATA rows='.count($rows).PHP_EOL;throw new RuntimeException('Metadata row budget exceeded');}
        foreach($rows as $row){foreach((array)$row as $value){if(is_string($value)&&strlen($value)>$bytes){echo 'UNBOUNDED_METADATA bytes='.strlen($value).PHP_EOL;throw new RuntimeException('Metadata field budget exceeded');}}}
        return $rows;
    }
}

// The database is either a fresh private SQLite file or the owned no-network MySQL runner.
$mysql=($argv[1]??'sqlite')==='mysql';
if($mysql){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||!is_file(dirname($socket).'/account-test-owner')||is_link(dirname($socket))){throw new RuntimeException('Owned MySQL required');}}
$selected=$argv[2]??'all';
$modes=['canonical','trigger','extra-column','long-type','wide-columns','missing-index','wrong-order','unique-index'];
$modes=array_merge($modes,$mysql?['prefix-index']:['partial-index','many-indexes','long-index','wrong-owner','temp-trigger','shadow-module']);
foreach(['inbox','processing'] as $target){foreach($modes as $mode){
    if(isset($argv[3])&&$argv[3]!==$target){continue;}
    if($selected!=='all'&&$selected!==$mode){continue;}
    $e=new InboxEnvironment($mysql);$table='sosecurity_webhook_'.$target;
    try{
        $e->pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[WebhookMetadataStatement::class,[$e->pdo]]);
        if($target==='processing'){
            $e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');
            foreach(explode(';',file_get_contents(dirname(__DIR__).'/resources/sql/webhook-processing-'.($mysql?'mysql':'sqlite').'.sql')) as $sql){if(trim($sql)!==''){$e->pdo->exec($sql);}}
        }
        $e->pdo->exec('CREATE TABLE webhook_schema_effects(value INTEGER NOT NULL)'.($mysql?' ENGINE=InnoDB':''));
        $index=$target==='inbox'?'sosecurity_webhook_retention':'sosecurity_webhook_pending';
        $columns=$target==='inbox'?'endpoint_key,created_at,event_key':'endpoint_key,status,due_at,receipt_id';
        if($mode==='trigger'){$e->pdo->exec('CREATE TRIGGER owned_webhook_trigger AFTER INSERT ON '.$table.' '.($mysql?'FOR EACH ROW INSERT INTO webhook_schema_effects VALUES(1)':'BEGIN INSERT INTO webhook_schema_effects VALUES(1); END'));}
        if($mode==='temp-trigger'){$e->pdo->exec('CREATE TEMP TRIGGER owned_webhook_trigger AFTER INSERT ON main.'.$table.' BEGIN INSERT INTO webhook_schema_effects VALUES(1); END');}
        if($mode==='extra-column'){$e->pdo->exec('ALTER TABLE '.$table.' ADD COLUMN extra INTEGER');}
        if($mode==='long-type'){
            if($mysql){$e->pdo->exec('ALTER TABLE '.$table." MODIFY COLUMN created_at ENUM('".str_repeat('x',200)."') NOT NULL");}
            else{$e->pdo->exec('ALTER TABLE '.$table.' ADD COLUMN extra '.str_repeat('X',8192));}
        }
        if($mode==='wide-columns'){for($i=0;$i<66;++$i){$e->pdo->exec('ALTER TABLE '.$table.' ADD COLUMN extra_'.$i.' INTEGER');}}
        if(in_array($mode,['missing-index','wrong-order','unique-index','partial-index','prefix-index'],true)){
            $e->pdo->exec('DROP INDEX '.$index.($mysql?' ON '.$table:''));
            if($mode!=='missing-index'){
                if($mode==='wrong-order'){$columns=implode(',',array_reverse(explode(',',$columns)));}
                if($mode==='prefix-index'){$columns=str_replace('endpoint_key','endpoint_key(8)',$columns);}
                $e->pdo->exec('CREATE '.($mode==='unique-index'?'UNIQUE ':'').'INDEX '.$index.' ON '.$table.'('.$columns.')'.($mode==='partial-index'?' WHERE 0':''));
            }
        }
        if($mode==='many-indexes'){$e->pdo->exec('BEGIN');for($i=0;$i<129;++$i){$e->pdo->exec('CREATE INDEX owned_extra_'.$i.' ON '.$table.'(endpoint_key)');}$e->pdo->exec('COMMIT');}
        if($mode==='long-index'){$e->pdo->exec('CREATE INDEX '.str_repeat('x',300).' ON '.$table.'(endpoint_key)');}
        if($mode==='wrong-owner'){
            $e->pdo->exec('DROP INDEX '.$index);$e->pdo->exec('CREATE TABLE webhook_schema_other(endpoint_key TEXT,created_at INTEGER,event_key TEXT,status TEXT,due_at INTEGER,receipt_id TEXT)');
            $e->pdo->exec('CREATE INDEX '.$index.' ON webhook_schema_other('.$columns.')');
        }
        if($mode==='shadow-module'){$e->pdo->exec('CREATE TEMP TABLE pragma_table_info(value TEXT)');}
        $run=static function()use($e,$mysql,$target):void{
            if($target==='inbox'){$e->receive();}
            else{ProcessingSchema::verify($e->pdo,$mysql?'mysql':'sqlite',new Deadline(10000));}
        };
        if($mode==='canonical'){$run();
            if($target==='processing'){
                $receipt=$e->receive();
                $processor=new SoSecurity\Webhook\SqlProcessor($e->pdo,'inbox-test-site',$e->endpoint,$e->seals,static function(string $body){$data=json_decode($body,true);return new SoSecurity\Webhook\Message($data['id'],$data['type'],$data['resource'],['version'=>$data['version']]);},static function(){return true;},static function(){return true;},null,$e->clock);
                $claim=$processor->claim($receipt->id(),'owned-worker');Check::same('leased',$claim->metadata()->status());
                $status=$processor->execute('owned-worker',$claim->token(),static function(PDO $pdo):bool{$pdo->exec('INSERT INTO webhook_schema_effects VALUES(1)');return true;});
                Check::same('succeeded',$status->status());
            }
            Check::same(1,$e->count());}
        else{$denied=false;try{$run();}catch(ConfigurationException $error){$denied=true;}
            if(!$denied){echo 'UNEXPECTED_ACCEPT '.json_encode(['target'=>$target,'mode'=>$mode,'receipts'=>$e->count(),'effects'=>(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_schema_effects')->fetchColumn()]).PHP_EOL;}
            Check::same(true,$denied);Check::same(0,$e->count());}
        Check::same($target==='processing'&&$mode==='canonical'?1:0,(int)$e->pdo->query('SELECT COUNT(*) FROM webhook_schema_effects')->fetchColumn());
        Check::same(false,$e->pdo->inTransaction());
        echo 'CASE '.$target.' '.$mode.' PASS'.PHP_EOL;
    }finally{
        if($mysql){$e->pdo->exec('DROP TABLE IF EXISTS sosecurity_webhook_processing');$e->pdo->exec('DROP TABLE IF EXISTS webhook_schema_effects');}
        $e->close();
    }
}}
echo 'PASS Webhook schema boundaries '.Check::$assertions.' assertions '.($mysql?'MySQL':'SQLite').' PHP '.PHP_VERSION.PHP_EOL;
