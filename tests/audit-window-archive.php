<?php
declare(strict_types=1);
// Only owned synthetic windows and ordinary first enqueue. No claim, delivery or ACK.
require __DIR__.'/bootstrap.php';
require __DIR__.'/webhook-inbox-support.php';

use SoSecurity\Audit\AlertOutboxPublisher;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Audit\WindowArchive;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\MySqlStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\HmacKeys;

final class AuditWindowOwnedCleanup extends RuntimeException {}

final class AuditWindowOwnedClock implements Clock
{
    public $time=120000;
    public $fault=false;
    public $onNow;
    public $privateMarker='PRIVATE-WINDOW-CLOCK';
    public function now():int
    {
        if($this->fault){throw new RuntimeException($this->privateMarker);}
        if($this->onNow!==null){($this->onNow)();}
        return $this->time;
    }
}

/** Real backing storage; hooks observe boundaries and retry only pure callbacks. */
final class AuditWindowOwnedStore implements AtomicStore
{
    private $store;
    public $inside=false;
    public $replay=false;
    public $before;
    public $after;
    public $fail=false;
    public $lastKey;
    public $lastValue;
    public $lastExpiry=0;
    public $callbackCalls=0;
    public function __construct(AtomicStore $store){$this->store=$store;}
    public function transact(string $key,callable $callback)
    {
        if($this->fail){throw new StorageException('PRIVATE-WINDOW-STORE','private.store',new RuntimeException('PRIVATE-WINDOW-CAUSE'));}
        if($this->before!==null){($this->before)();}
        $this->lastKey=$key;
        $result=$this->store->transact($key,function(?array $state)use($callback):Change{
            if($this->inside){throw new RuntimeException('Nested test store callback');}
            $this->inside=true;
            try{
                ++$this->callbackCalls;$first=$callback($state);
                if(!$first instanceof Change){throw new RuntimeException('Expected a concrete Change');}
                if($this->replay){
                    ++$this->callbackCalls;$second=$callback($state);
                    if(!$second instanceof Change||$first->value()!==$second->value()
                        ||$first->expiresAt()!==$second->expiresAt()||$first->result()!==$second->result()){
                        throw new RuntimeException('Atomic callback replay changed its result');
                    }
                }
                $this->lastValue=$first->value();$this->lastExpiry=$first->expiresAt();return $first;
            }finally{$this->inside=false;}
        });
        if($this->after!==null){($this->after)();}
        return $result;
    }
    public function replace(?array $state,int $expiry):void
    {
        if(!is_string($this->lastKey)){throw new RuntimeException('No owned archive key was observed');}
        $this->store->transact($this->lastKey,static function()use($state,$expiry):Change{return new Change($state,$expiry,null);});
    }
}

function auditWindowError(callable $operation,?string $reason=null,string $type=SecurityException::class):Throwable
{
    ++Check::$assertions;$caught=null;
    try{$operation();}catch(Throwable $error){$caught=$error;}
    if($caught===null){throw new RuntimeException('Expected a fixed audit window refusal');}
    if(!$caught instanceof $type){throw new RuntimeException('Unexpected audit window exception class');}
    if($reason!==null){Check::same($reason,$caught->reason());}
    return $caught;
}

function auditWindowPrivate(Throwable $error):void
{
    Check::same(null,$error->getPrevious());
    Check::same(false,strpos((string)$error,'PRIVATE-WINDOW')!==false);
}

function auditWindowRecord(MetricsSink $metrics,string $event='login.failed'):void
{
    // The event timestamp deliberately differs from the Metrics clock.
    $metrics(['time'=>17,'event'=>$event,'scope'=>'tenant',
        'subject'=>str_repeat('a',64),'context'=>['allowed'=>false,'status'=>401]]);
}

function auditWindowMysqlSocket():string
{
    $socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');
    if(!is_string($socket)||preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)!==1
        ||is_link(dirname($socket))||!is_file(dirname($socket).'/account-test-owner')
        ||is_link(dirname($socket).'/account-test-owner')){
        throw new RuntimeException('Use only the controller-owned no-TCP MySQL instance');
    }
    return $socket;
}

function auditWindowConnection(bool $mysql,string $database):InboxTestConnection
{
    $dsn=$mysql?'mysql:unix_socket='.auditWindowMysqlSocket().';dbname=sosecurity_test;charset=utf8mb4':'sqlite:'.$database;
    $options=[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1];
    if($mysql){$options[PDO::ATTR_EMULATE_PREPARES]=false;}
    $pdo=new InboxTestConnection($dsn,$mysql?'sosecurity_test':null,$mysql?'integration-only':null,$options);
    $pdo->setAttribute(PDO::ATTR_STATEMENT_CLASS,[InboxTestStatement::class,[$pdo]]);
    if($mysql){Check::same('sosecurity_test',$pdo->query('SELECT DATABASE()')->fetchColumn());}
    else{$pdo->exec('PRAGMA journal_mode=DELETE');$pdo->exec('PRAGMA synchronous=FULL');$pdo->exec('PRAGMA busy_timeout=1000');}
    return $pdo;
}

final class AuditWindowOwnedEnvironment
{
    public $mysql;
    public $directory;
    public $clock;
    public $pdo;
    public $observer;
    public $archivePdo;
    public $metricsPdo;
    public $metricsStore;
    public $archiveStore;
    public $metrics;
    public $stores=[];
    public $readAllowed=true;
    public $writeAllowed=true;
    public $permissionCalls=[];
    public $permissionHook;
    public $queueAllowed=true;
    public $authorityHook;
    private $created=[];
    private $owner;
    private $closed=false;
    public function __construct(bool $mysql)
    {
        $this->mysql=$mysql;$this->directory=privateDirectory();$this->clock=new AuditWindowOwnedClock();
        $this->owner=bin2hex(random_bytes(16));
        file_put_contents($this->directory.'/window-archive-owner',$this->owner);chmod($this->directory.'/window-archive-owner',0600);
        try{
            $database=$this->directory.'/outbox.sqlite';$this->pdo=auditWindowConnection($mysql,$database);
            $sql=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/outbox-'.($mysql?'mysql':'sqlite').'.sql'));
            if(stripos($sql,'IF NOT EXISTS')!==false){throw new RuntimeException('Strict owned Outbox table creation required');}
            foreach(explode(';',$sql) as $statement){
                $statement=trim($statement);if($statement===''){continue;}$this->pdo->exec($statement);
                if(preg_match('/\ACREATE TABLE\s+(sosecurity_outbox_(?:roots|records))\b/i',$statement,$match)){$this->created[]=$match[1];}
            }
            Check::same(2,count($this->created));$this->observer=auditWindowConnection($mysql,$database);
            if($mysql){
                $schema=file_get_contents(dirname(__DIR__).'/resources/sql/mysql.sql');
                if(substr_count($schema,'CREATE TABLE IF NOT EXISTS sosecurity_state')!==1){throw new RuntimeException('Unexpected owned atomic schema');}
                // Refuse an existing table. Never adopt or drop another test's data.
                $this->pdo->exec(str_replace('CREATE TABLE IF NOT EXISTS sosecurity_state','CREATE TABLE sosecurity_state',$schema));
                $this->created[]='sosecurity_state';
                $this->archivePdo=auditWindowConnection(true,$database);$this->metricsPdo=auditWindowConnection(true,$database);
                Check::same(false,$this->archivePdo===$this->pdo);Check::same(false,$this->archivePdo===$this->metricsPdo);
            }
            $this->metricsStore=$this->wrap(new FileStore($this->directory,'owned-window-metrics',$this->clock));
            $base=$mysql?new MySqlStore($this->archivePdo,'owned-window-archive',$this->clock):new FileStore($this->directory,'owned-window-archive',$this->clock);
            $this->archiveStore=$this->wrap($base);$this->metrics=$this->makeMetrics($this->metricsStore,$this->clock);
            $this->archiveStore->before=function():void{Check::same(false,$this->metricsStore->inside);};
        }catch(Throwable $error){$this->close();throw $error;}
    }
    public function wrap(AtomicStore $store):AuditWindowOwnedStore
    {$wrapped=new AuditWindowOwnedStore($store);$this->stores[]=$wrapped;return $wrapped;}
    public function makeMetrics(AtomicStore $store,Clock $clock,string $site='owned-window-site',int $threshold=1,int $retained=2):MetricsSink
    {return new MetricsSink($store,$site,['login.failed'=>'authentication','policy.denied'=>'authorization'],
        ['authentication'=>$threshold,'authorization'=>1],8,60,static function(array $record):void{},$clock,$retained);}
    public function permission():callable
    {
        return function(string $action):bool{
            foreach($this->stores as $store){Check::same(false,$store->inside);}
            Check::same(true,in_array($action,['read','write'],true));$this->permissionCalls[]=$action;
            if($this->permissionHook!==null){($this->permissionHook)($action);}
            return $action==='read'?$this->readAllowed:$this->writeAllowed;
        };
    }
    public function archive(int $capacity=4,int $retention=600,int $timeout=1000):WindowArchive
    {return new WindowArchive($this->metrics,$this->archiveStore,$this->permission(),$capacity,$retention,$this->clock,$timeout);}
    public function closed():array
    {auditWindowRecord($this->metrics);$snapshot=$this->metrics->inspect();$this->clock->time=$snapshot['expires_at'];return $snapshot;}
    public function queue(?Policy $policy=null):SqlOutbox
    {
        $queue=new SqlOutbox($this->pdo,'owned-window-outbox',str_repeat('e',64),new HmacKeys('owned',['owned'=>str_repeat('k',32)]),
            function(string $action,string $phase,string $scope,string $producer,string $actor,array $metadata):bool{
                if($this->authorityHook!==null){($this->authorityHook)($action,$phase);}
                return $this->queueAllowed;
            },$policy,$this->clock,static function():bool{return true;});
        Check::same(true,$queue->initialize('tenant',AlertOutboxPublisher::producer(),'owned-admin'));return $queue;
    }
    public function transaction(callable $body,bool $commit=true)
    {
        $this->pdo->exec($this->mysql?'START TRANSACTION':'BEGIN IMMEDIATE');
        try{$result=$body();$this->pdo->exec($commit?'COMMIT':'ROLLBACK');return $result;}
        catch(Throwable $error){$this->pdo->exec('ROLLBACK');throw $error;}
    }
    public function rows():array
    {return $this->observer->query('SELECT * FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);}
    public function close():void
    {
        if($this->closed){return;}$this->closed=true;
        $failed=false;
        try{
        foreach([$this->pdo,$this->archivePdo,$this->metricsPdo,$this->observer] as $pdo){
            if(!$pdo instanceof InboxTestConnection){continue;}
            $pdo->beforeStatement=null;$pdo->afterStatement=null;$pdo->afterExec=null;$pdo->beforeCommit=null;$pdo->afterCommit=null;
            try{$pdo->exec('ROLLBACK');}catch(Throwable $ignored){}
        }
        if($this->mysql&&$this->pdo instanceof PDO){foreach(array_reverse($this->created) as $table){$this->pdo->exec('DROP TABLE '.$table);}}
        $this->stores=[];$this->metrics=null;$this->archiveStore=null;$this->metricsStore=null;
        $this->observer=null;$this->archivePdo=null;$this->metricsPdo=null;$this->pdo=null;
        if(is_link($this->directory)||file_get_contents($this->directory.'/window-archive-owner')!==$this->owner){throw new RuntimeException('Owned test directory identity changed');}
        foreach(new DirectoryIterator($this->directory) as $entry){
            if($entry->isDot()){continue;}if($entry->isDir()&&!$entry->isLink()){throw new RuntimeException('Unexpected owned nested resource');}unlink($entry->getPathname());
        }
        rmdir($this->directory);
        }catch(Throwable $error){$failed=true;}
        if($failed){throw new AuditWindowOwnedCleanup('Owned audit window resource cleanup is incomplete');}
    }
    public function concurrentManifest():string
    {
        $manifest=['owner'=>$this->owner,'directory'=>$this->directory,'mysql'=>$this->mysql,'time'=>$this->clock->time];
        $path=$this->directory.'/window-worker.json';file_put_contents($path,json_encode($manifest));chmod($path,0600);return $path;
    }
}

/** Worker only opens parent-owned state. It never creates/drops SQL tables or cleans parent resources. */
function auditWindowWorker(string $manifestPath,string $index):void
{
    if(preg_match('/\A[0-2]\z/D',$index)!==1||is_link($manifestPath)||basename($manifestPath)!=='window-worker.json'){
        throw new RuntimeException('Use an exact owned window worker manifest');
    }
    $directory=dirname($manifestPath);$base=realpath(sys_get_temp_dir());$real=realpath($directory);
    if($real!==$directory||$base===false||dirname($real)!==$base||is_link($directory)
        ||preg_match('/\Asosecurity-test-[a-f0-9]{16}\z/D',basename($real))!==1||(fileperms($real)&0077)!==0){
        throw new RuntimeException('Worker storage is not an owned private test directory');
    }
    $raw=file_get_contents($manifestPath,false,null,0,4097);$manifest=json_decode($raw,true,4);
    if(!is_array($manifest)||array_keys($manifest)!==['owner','directory','mysql','time']||$manifest['directory']!==$real
        ||!is_bool($manifest['mysql'])||!is_int($manifest['time'])||$manifest['time']!==120060
        ||!is_string($manifest['owner'])||preg_match('/\A[a-f0-9]{32}\z/D',$manifest['owner'])!==1
        ||is_link($real.'/window-archive-owner')||file_get_contents($real.'/window-archive-owner')!==$manifest['owner']){
        throw new RuntimeException('Worker ownership marker differs');
    }
    $ready=fopen($real.'/worker-ready-'.$index,'x');if($ready===false){throw new RuntimeException('Worker ready marker already exists');}fclose($ready);
    $deadline=new Deadline(10000);
    while(!is_file($real.'/worker-go')){$deadline->check('test.worker_timeout');usleep(1000);}
    $clock=new AuditWindowOwnedClock();$clock->time=$manifest['time'];
    $metrics=new MetricsSink(new FileStore($real,'owned-window-metrics',$clock),'owned-window-site',
        ['login.failed'=>'authentication','policy.denied'=>'authorization'],['authentication'=>1,'authorization'=>1],8,60,static function(array $record):void{},$clock,2);
    $store=$manifest['mysql']?new MySqlStore(auditWindowConnection(true,''),'concurrent-window-archive',$clock)
        :new FileStore($real,'concurrent-window-archive',$clock);
    $archive=new WindowArchive($metrics,$store,static function(string $action):bool{return true;},1,600,$clock,10000);
    Check::same([120000],$archive->checkpointClosedWindows());
    echo 'WORKER audit window archive saved '.$index.' 120000'.PHP_EOL;
}

function auditWindowConcurrent(AuditWindowOwnedEnvironment $e,array $snapshot):void
{
    $manifest=$e->concurrentManifest();$processes=[];$failure=null;
    try{
        for($index=0;$index<3;++$index){
            $command='exec '.implode(' ',array_map('escapeshellarg',[PHP_BINARY,__FILE__,'worker',$manifest,(string)$index]));
            $pipes=[];$process=proc_open($command,[0=>['pipe','r'],1=>['file',$e->directory.'/worker-'.$index.'.log','w'],
                2=>['file',$e->directory.'/worker-'.$index.'.error','w']],$pipes,dirname(__DIR__));
            if(!is_resource($process)){throw new RuntimeException('Cannot start an owned window worker');}fclose($pipes[0]);$processes[]=$process;
        }
        $deadline=new Deadline(10000);
        while(true){$ready=0;for($index=0;$index<3;++$index){if(is_file($e->directory.'/worker-ready-'.$index)){++$ready;}}
            if($ready===3){break;}$deadline->check('test.worker_timeout');usleep(1000);}
        $go=fopen($e->directory.'/worker-go','x');if($go===false){throw new RuntimeException('Owned start marker exists');}fclose($go);
        foreach($processes as $index=>$process){
            while(true){$status=proc_get_status($process);if(!$status['running']){break;}$deadline->check('test.worker_timeout');usleep(1000);}
            $code=proc_close($process);$processes[$index]=null;if($code===-1){$code=$status['exitcode'];}Check::same(0,$code);
            Check::same('WORKER audit window archive saved '.$index.' 120000'.PHP_EOL,file_get_contents($e->directory.'/worker-'.$index.'.log'));
            Check::same('',file_get_contents($e->directory.'/worker-'.$index.'.error'));
        }
    }catch(Throwable $error){$failure=$error;}
    finally{
        foreach($processes as $process){if(is_resource($process)){proc_terminate($process);proc_close($process);}}
    }
    if($failure!==null){throw $failure;}
    $base=$e->mysql?new MySqlStore($e->archivePdo,'concurrent-window-archive',$e->clock)
        :new FileStore($e->directory,'concurrent-window-archive',$e->clock);
    $archive=new WindowArchive($e->metrics,$base,$e->permission(),1,600,$e->clock);
    Check::same($snapshot,$archive->window(120000));Check::same([120000],$archive->checkpointClosedWindows());
}

function auditWindowCase(string $case,AuditWindowOwnedEnvironment $e):void
{
    if($case==='configuration'){
        Check::same(null,$e->metrics->archiveProfile(new AuditWindowOwnedClock()));
        Check::same(true,is_array($e->metrics->archiveProfile($e->clock)));
        foreach([[0,600,1000],[65,600,1000],[1,0,1000],[1,31536001,1000],[1,600,0],[1,600,30001]] as $input){
            auditWindowError(function()use($e,$input):void{$e->archive($input[0],$input[1],$input[2]);},null,ConfigurationException::class);
        }
        $legacy=$e->makeMetrics($e->metricsStore,$e->clock,'legacy-window-site',1,0);
        auditWindowError(function()use($legacy,$e):void{new WindowArchive($legacy,$e->archiveStore,$e->permission(),1,600,$e->clock);},null,ConfigurationException::class);
        auditWindowError(function()use($e):void{new WindowArchive($e->metrics,$e->archiveStore,$e->permission(),1,600,new AuditWindowOwnedClock());},null,ConfigurationException::class);
        $archive=$e->archive();Check::same(true,$archive->matches($e->metrics));
        Check::same(false,strpos(var_export($archive,true),$e->directory)!==false);
        Check::same(false,strpos(var_export($archive,true),'PRIVATE-WINDOW-CLOCK')!==false);
        auditWindowError(function()use($archive):void{serialize($archive);},null,ConfigurationException::class);
        return;
    }
    if($case==='closed-only'){
        auditWindowRecord($e->metrics);$current=$e->metrics->inspect();$archive=$e->archive();
        Check::same([],$archive->checkpointClosedWindows());
        auditWindowError(function()use($archive,$current):void{$archive->window($current['window_start']);},'audit.window_missing');
        $e->clock->time=$current['expires_at'];auditWindowRecord($e->metrics);$before=$e->metrics->inspect();
        Check::same([$current['window_start']],$archive->checkpointClosedWindows());
        Check::same($current,$archive->window($current['window_start']));Check::same($before,$e->metrics->inspect());
        auditWindowError(function()use($archive,$before):void{$archive->window($before['window_start']);},'audit.window_missing');return;
    }
    $snapshot=$e->closed();$start=$snapshot['window_start'];$archive=$e->archive($case==='capacity'?1:4,$case==='outbox-expired'?200000:600);
    if($case==='window-conflict'){
        Check::same([$start],$archive->checkpointClosedWindows());$clock=new AuditWindowOwnedClock();
        $other=$e->makeMetrics(new FileStore($e->directory,'conflicting-window-metrics',$clock),$clock);
        auditWindowRecord($other);auditWindowRecord($other);$clock->time=120060;
        $conflict=new WindowArchive($other,$e->archiveStore,$e->permission(),4,600,$clock);
        auditWindowError(function()use($conflict):void{$conflict->checkpointClosedWindows();},'audit.window_conflict');
        Check::same($snapshot,$archive->window($start));auditWindowConcurrent($e,$snapshot);return;
    }
    if($case==='write-revoked'){
        $e->writeAllowed=false;auditWindowError(function()use($archive):void{$archive->checkpointClosedWindows();},'audit.window_forbidden');
        $e->writeAllowed=true;$e->archiveStore->after=function()use($e):void{$e->writeAllowed=false;};
        auditWindowError(function()use($archive):void{$archive->checkpointClosedWindows();},'audit.window_forbidden');
        $e->archiveStore->after=null;$e->writeAllowed=true;
        // The checkpoint commit was confirmed before final authorization failed; it is not rolled back.
        Check::same($snapshot,$archive->window($start));
        $mainStored=false;$deleted=false;
        $e->archiveStore->after=static function()use(&$mainStored):void{$mainStored=true;};
        $e->permissionHook=static function(string $action)use($e,&$mainStored,&$deleted):void{
            if($action==='write'&&$mainStored&&!$deleted){
                Check::same(false,$e->archiveStore->inside);$deleted=true;
                $e->archiveStore->replace(null,0);
            }
        };
        // The last permission callback deletes a confirmed copy. Do not return its old saved list.
        auditWindowError(function()use($archive):void{$archive->checkpointClosedWindows();},'audit.window_missing');
        Check::same(true,$deleted);$e->archiveStore->after=null;$e->permissionHook=null;
        auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_missing');
        Check::same([],$e->rows());return;
    }
    if($case==='callback-purity'){
        $before=count($e->permissionCalls);$normalCallbacks=$e->archiveStore->callbackCalls;
        Check::same([$start],$archive->checkpointClosedWindows());$normal=count($e->permissionCalls)-$before;
        $normalCallbacks=$e->archiveStore->callbackCalls-$normalCallbacks;Check::same(true,$normalCallbacks>0);
        $e->metricsStore->replay=true;$e->archiveStore->replay=true;$before=count($e->permissionCalls);$calls=$e->archiveStore->callbackCalls;
        Check::same([$start],$archive->checkpointClosedWindows());Check::same($normal,count($e->permissionCalls)-$before);
        Check::same(2*$normalCallbacks,$e->archiveStore->callbackCalls-$calls);$before=count($e->permissionCalls);$archive->window($start);$reads=count($e->permissionCalls)-$before;
        $e->archiveStore->replay=false;$before=count($e->permissionCalls);$archive->window($start);Check::same($reads,count($e->permissionCalls)-$before);return;
    }
    if($case==='permission-fault'){
        $e->permissionHook=static function():void{throw new RuntimeException('PRIVATE-WINDOW-PERMISSION');};
        auditWindowPrivate(auditWindowError(function()use($archive):void{$archive->checkpointClosedWindows();}));
        $e->permissionHook=null;Check::same([$start],$archive->checkpointClosedWindows());
        $e->permissionHook=static function():void{throw new RuntimeException('PRIVATE-WINDOW-PERMISSION');};
        auditWindowPrivate(auditWindowError(function()use($archive,$start):void{$archive->window($start);}));
        $e->permissionHook=static function()use($archive,$start):void{
            try{$archive->window($start);}catch(SecurityException $inner){Check::same('audit.window_reentry',$inner->reason());}
        };
        auditWindowPrivate(auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_reentry'));return;
    }
    if($case==='storage-fault'){
        $e->archiveStore->fail=true;auditWindowPrivate(auditWindowError(function()use($archive):void{$archive->checkpointClosedWindows();},'audit.window_storage'));
        $e->archiveStore->fail=false;Check::same([$start],$archive->checkpointClosedWindows());$e->archiveStore->fail=true;
        auditWindowPrivate(auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_storage'));return;
    }
    Check::same([$start],$archive->checkpointClosedWindows());
    if($case==='source-expired'){
        $e->clock->time=$snapshot['expires_at']+180;Check::same(1,count($e->metrics->inspectRetained()));
        Check::same([],$e->metrics->inspect()['alerts']);$before=$e->metrics->inspect();
        $rebuilt=$e->archive();Check::same($snapshot,$rebuilt->window($start));$queue=$e->queue();$publisher=new AlertOutboxPublisher($e->metrics,$queue,'tenant','owned-operator');
        $rows=$e->transaction(function()use($publisher,$rebuilt,$start):array{return $publisher->publishArchived($rebuilt,$start);});
        Check::same(1,count($rows));Check::same($before,$e->metrics->inspect());Check::same('pending',$rows[0]->state());return;
    }
    if($case==='missing-expired'){
        auditWindowError(function()use($archive,$start):void{$archive->window($start-60);},'audit.window_missing');
        ++$e->clock->time;Check::same([$start],$archive->checkpointClosedWindows());
        $e->clock->time=$snapshot['expires_at']+599;Check::same($snapshot,$archive->window($start));
        Check::same([],$archive->checkpointClosedWindows());++$e->clock->time;
        auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_missing');return;
    }
    if($case==='capacity'){
        auditWindowRecord($e->metrics);$second=$e->metrics->inspect();$e->clock->time=$second['expires_at'];
        auditWindowError(function()use($archive):void{$archive->checkpointClosedWindows();},'audit.window_capacity');
        Check::same($snapshot,$archive->window($start));auditWindowError(function()use($archive,$second):void{$archive->window($second['window_start']);},'audit.window_missing');return;
    }
    if($case==='corrupt'){
        $good=$e->archiveStore->lastValue;$expiry=$e->archiveStore->lastExpiry;
        $e->archiveStore->replace(['v'=>99,'private'=>'PRIVATE-WINDOW-CORRUPT'],$expiry);
        auditWindowPrivate(auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_corrupt'));
        $e->archiveStore->replace($good,$expiry);Check::same($snapshot,$archive->window($start));
        $large=$good;$large['private']=str_repeat('x',32769);$e->archiveStore->replace($large,$expiry);
        auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_corrupt');return;
    }
    if($case==='read-revoked'){
        $e->readAllowed=false;auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_forbidden');
        $e->readAllowed=true;$e->archiveStore->after=function()use($e):void{$e->readAllowed=false;};
        auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_forbidden');
        $e->archiveStore->after=null;$e->readAllowed=true;$queue=$e->queue();
        $publisher=new AlertOutboxPublisher($e->metrics,$queue,'tenant','owned-operator');$lateRevoked=false;
        $e->authorityHook=static function(string $action,string $phase)use($e,&$lateRevoked):void{
            if($action==='enqueue'&&$phase==='commit'){$lateRevoked=true;$e->readAllowed=false;}
        };
        auditWindowError(function()use($e,$publisher,$archive,$start):void{
            $e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start);});
        },'audit.window_forbidden');
        Check::same(true,$lateRevoked);Check::same([],$e->rows());$e->readAllowed=true;
        Check::same($snapshot,$archive->window($start));$mainRead=false;$deleted=false;
        $e->archiveStore->after=static function()use(&$mainRead):void{$mainRead=true;};
        $e->permissionHook=static function(string $action)use($e,&$mainRead,&$deleted):void{
            if($action==='read'&&$mainRead&&!$deleted){
                Check::same(false,$e->archiveStore->inside);$deleted=true;
                $e->archiveStore->replace(null,0);
            }
        };
        // The last permission callback deletes the source after its main read completed.
        auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_missing');
        Check::same(true,$deleted);Check::same([],$e->rows());return;
    }
    if($case==='clock'){
        $e->clock->time=120059;auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_clock');
        $e->clock->time=120060;$e->clock->fault=true;
        auditWindowPrivate(auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_clock'));
        $e->clock->fault=false;$installed=false;$revoked=false;
        $e->archiveStore->after=static function()use($e,&$installed,&$revoked):void{
            if($installed){return;}$installed=true;
            // Install only after the real main store transaction returned. The next archive now()
            // is outside that callback; backend Codec/MySqlStore clock reads cannot trigger it early.
            $e->clock->onNow=static function()use($e,&$revoked):void{
                $e->clock->onNow=null;foreach($e->stores as $store){Check::same(false,$store->inside);}
                $revoked=true;$e->readAllowed=false;
            };
        };
        auditWindowError(function()use($archive,$start):void{$archive->window($start);},'audit.window_forbidden');
        Check::same(true,$installed);Check::same(true,$revoked);return;
    }
    if($case==='metrics-store'){
        $store=$e->mysql?new MySqlStore($e->metricsPdo,'owned-sql-window-metrics',$e->clock)
            :new FileStore($e->directory,'owned-second-window-metrics',$e->clock);
        $wrapped=$e->wrap($store);$metrics=$e->makeMetrics($wrapped,$e->clock,'independent-metrics-window');
        auditWindowRecord($metrics);$view=$metrics->inspect();$e->clock->time=$view['expires_at'];
        $base=$e->mysql?new MySqlStore($e->archivePdo,'independent-window-archive',$e->clock)
            :new FileStore($e->directory,'independent-window-archive',$e->clock);
        $independent=$e->wrap($base);$independent->before=function()use($wrapped):void{Check::same(false,$wrapped->inside);};
        $other=new WindowArchive($metrics,$independent,$e->permission(),4,600,$e->clock);
        Check::same([$view['window_start']],$other->checkpointClosedWindows());$queue=$e->queue();$publisher=new AlertOutboxPublisher($metrics,$queue,'tenant','owned-operator');
        $statuses=$e->transaction(function()use($publisher,$other,$view):array{return $publisher->publishArchived($other,$view['window_start']);});
        Check::same(1,count($statuses));Check::same(1,count($e->rows()));return;
    }
    $queue=$e->queue();$publisher=new AlertOutboxPublisher($e->metrics,$queue,'tenant','owned-operator');
    if($case==='publisher-mismatch'){
        foreach([['owned-window-site',1],['owned-window-site',2],['other-window-site',1]] as $i=>$spec){
            $other=$e->makeMetrics(new FileStore($e->directory,'mismatch-window-'.$i,$e->clock),$e->clock,$spec[0],$spec[1]);
            Check::same(false,$archive->matches($other));$wrong=new AlertOutboxPublisher($other,$queue,'tenant','owned-operator');
            auditWindowError(function()use($e,$wrong,$archive,$start):void{$e->transaction(function()use($wrong,$archive,$start):array{return $wrong->publishArchived($archive,$start);});},'configuration.audit_archive',ConfigurationException::class);
            if($spec[0]==='owned-window-site'&&$spec[1]===2){
                $changed=new WindowArchive($other,$e->archiveStore,$e->permission(),4,600,$e->clock);
                auditWindowError(function()use($changed,$start):void{$changed->window($start);},'configuration.audit_window_policy',ConfigurationException::class);
            }
        }Check::same([],$e->rows());return;
    }
    if($case==='deadline'){
        $e->permissionHook=static function():void{usleep(20000);};
        auditWindowError(function()use($archive,$start):void{$archive->window($start,new Deadline(5));},'audit.window_timeout');
        $short=$e->archive(4,600,5);auditWindowError(function()use($short):void{$short->checkpointClosedWindows();},'audit.window_timeout');
        $e->permissionHook=null;$delayed=false;$e->authorityHook=static function(string $action,string $phase)use(&$delayed):void{
            if(!$delayed&&$action==='enqueue'&&$phase==='current'){$delayed=true;usleep(1100000);}
        };
        auditWindowError(function()use($e,$publisher,$archive,$start):void{$e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start,1000);});},'audit.window_timeout');
        Check::same(true,$delayed);Check::same([],$e->rows());return;
    }
    if($case==='outbox-denied'){
        $e->queueAllowed=false;
        auditWindowError(function()use($e,$publisher,$archive,$start):void{$e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start);});},'outbox.denied');
        Check::same([],$e->rows());Check::same($snapshot,$archive->window($start));return;
    }
    if($case==='outbox-expired'){
        $e->clock->time=$start+86400;
        Check::same($snapshot,$archive->window($start));
        auditWindowError(function()use($e,$publisher,$archive,$start):void{$e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start);});},'outbox.expired');
        Check::same([],$e->rows());return;
    }
    if($case==='rollback'){
        $first=$e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start);},false);
        Check::same(1,count($first));Check::same([],$e->rows());
        $second=$e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start);});
        Check::same($first[0]->id(),$second[0]->id());Check::same(1,count($e->rows()));return;
    }
    if($case!=='publish-identity'){throw new RuntimeException('Unknown fixed audit window case');}
    $ordinary=$e->transaction(function()use($publisher):array{return $publisher->publish();});$before=$e->rows();
    $first=$e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start);});
    $second=$e->transaction(function()use($publisher,$archive,$start):array{return $publisher->publishArchived($archive,$start);});
    Check::same(1,count($ordinary));Check::same($ordinary[0]->id(),$first[0]->id());Check::same($first[0]->id(),$second[0]->id());
    Check::same($before,$e->rows());$row=$before[0];
    Check::same(Message::identifier('audit-alert:'.$e->metrics->siteBinding().':authentication:'.$start,$start),$row['message_id']);
    Check::same('pending',$row['status']);Check::same(0,(int)$row['attempts']);Check::same(0,(int)$row['generation']);
    Check::same(0,(int)$row['sent_at']);Check::same($start,(int)$row['created_at']);
    Check::same(['v'=>1,'site_binding'=>$e->metrics->siteBinding(),'class'=>'authentication',
        'window_start'=>$start,'expires_at'=>$snapshot['expires_at']],json_decode($row['payload_body'],true));
    Check::same(false,strpos(json_encode($e->archiveStore->lastValue),str_repeat('a',64))!==false);
}

if(($argv[1]??'')==='worker'){
    if(count($argv)!==4){throw new RuntimeException('Use one owned worker manifest and index');}
    auditWindowWorker($argv[2],$argv[3]);exit(0);
}
$ownedBackend=$argv[1]??'sqlite';$ownedCase=$argv[2]??'all';
$ownedCases=['configuration','closed-only','source-expired','publish-identity','missing-expired',
    'publisher-mismatch','window-conflict','capacity','corrupt','write-revoked','read-revoked',
    'permission-fault','storage-fault','deadline','clock','callback-purity','outbox-denied',
    'outbox-expired','rollback','metrics-store'];
if(!in_array($ownedBackend,['sqlite','mysql'],true)||!in_array($ownedCase,array_merge($ownedCases,['all']),true)){
    throw new RuntimeException('Use sqlite|mysql and a fixed audit-window-archive case');
}
$ownedFailures=0;
foreach($ownedCase==='all'?$ownedCases:[$ownedCase] as $mode){
    echo 'BEGIN audit window archive '.$mode.' PHP '.PHP_VERSION.' '.$ownedBackend.PHP_EOL;
    $assertions=Check::$assertions;$environment=null;$error=null;$cleanupFailed=false;
    try{$environment=new AuditWindowOwnedEnvironment($ownedBackend==='mysql');auditWindowCase($mode,$environment);}
    catch(Throwable $caught){$error=$caught;$cleanupFailed=$caught instanceof AuditWindowOwnedCleanup;}
    finally{
        if($environment!==null){try{$environment->close();}catch(Throwable $cleanup){$cleanupFailed=true;$error=$cleanup;}}
    }
    if($error!==null){
        ++$ownedFailures;$reason=method_exists($error,'reason')?$error->reason():'assertion_or_fixture';
        if(!is_string($reason)||preg_match('/\A[a-z][a-z0-9_.-]{0,95}\z/D',$reason)!==1){$reason='unexpected_reason';}
        $line=$error->getFile()===__FILE__?$error->getLine():0;
        foreach($error->getTrace() as $frame){if(($frame['file']??null)===__FILE__&&isset($frame['line'])){$line=$frame['line'];break;}}
        echo 'FAIL audit window archive '.$mode.' class '.get_class($error).' reason '.$reason
            .' test_line='.$line.' assertion='.(Check::$assertions-$assertions)
            .' cleanup_failed='.($cleanupFailed?'true':'false').' PHP '.PHP_VERSION.' '.$ownedBackend.PHP_EOL;
        if($cleanupFailed){break;}
    }else{
        echo 'PASS audit window archive '.$mode.' '.(Check::$assertions-$assertions).' assertions PHP '
            .PHP_VERSION.' '.$ownedBackend.'; owned checkpoints and first enqueue only'.PHP_EOL;
    }
}
exit($ownedFailures===0?0:1);
