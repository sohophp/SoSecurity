<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/examples/outbox-business.php';

use SoSecurity\Examples\Outbox as Receiver;

function recoverySettings(string $file):array
{
    $before=getenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$file);
    try{return Receiver\settings('receiver');}
    finally{if($before===false){putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');}else{putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$before);}}
}
function recoveryJson(string $file,array $value):void {file_put_contents($file,json_encode($value));chmod($file,0600);clearstatcache(true,$file);}
final class ReceiverRecoveryCommitFault extends PDO
{
    public $phase;
    public function commit():bool
    {
        if($this->phase==='before'){throw new RuntimeException('test commit before');}
        $result=parent::commit();if($this->phase==='after'){throw new RuntimeException('test commit after');}return $result;
    }
}
final class ReceiverRecoveryEnvironment
{
    public $directory;
    public $file;
    public $config;
    public $created;
    public function __construct(bool $initialize=true)
    {
        $this->directory=privateDirectory();$d=$this->directory;$this->created=time();
        mkdir($d.'/web',0700);mkdir($d.'/state',0700);
        $pdo=new PDO('sqlite:'.$d.'/business.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($d.'/business.sqlite',0600);
        foreach(['webhook-sqlite','webhook-processing-sqlite','outbox-example-receiver-sqlite'] as $name){$pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/'.$name.'.sql'));}
        $pdo->exec("INSERT INTO outbox_example_actors VALUES('receiver','1',1,'[\"receiver_worker\",\"receiver_admin\"]')");
        $pdo->exec("INSERT INTO outbox_example_routes VALUES('outbox-publisher','outbox-example',1)");$pdo->exec("INSERT INTO outbox_example_owners VALUES('alice',1)");$pdo=null;
        $pdo=new PDO('sqlite:'.$d.'/checkpoint.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($d.'/checkpoint.sqlite',0600);$pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/outbox-example-checkpoint-sqlite.sql'));$pdo=null;
        file_put_contents($d.'/checkpoint.lock','');chmod($d.'/checkpoint.lock',0600);
        foreach(['seals'=>'s','wire'=>'w'] as $purpose=>$byte){recoveryJson($d.'/'.$purpose.'.json',['current'=>'old','keys'=>['old'=>base64_encode(str_repeat($byte,32))]]);}
        $this->config=['role'=>'receiver','document_root'=>$d.'/web','database'=>$d.'/business.sqlite','checkpoint_database'=>$d.'/checkpoint.sqlite','checkpoint_lock'=>$d.'/checkpoint.lock','storage'=>$d.'/state','actor'=>'receiver','version'=>'1','epoch'=>str_repeat('e',64),'seals'=>$d.'/seals.json','wire_keys'=>$d.'/wire.json','url'=>'https://receiver.example.com/outbox-receiver.php'];
        $this->file=$d.'/receiver.json';$this->configure([]);if($initialize){Receiver\receiverInitialize($this->settings());}
    }
    public function configure(array $changes):void {$this->config=array_replace($this->config,$changes);recoveryJson($this->file,$this->config);}
    public function settings():array {return recoverySettings($this->file);}
    public function pdo(bool $checkpoint=false):PDO {return new PDO('sqlite:'.$this->config[$checkpoint?'checkpoint_database':'database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);}
    public function body(int $index=1):string
    {
        $order=substr(hash('sha256','recovery-order-'.$index),0,32);
        return json_encode(['event_id'=>SoSecurity\Outbox\Message::identifier($order,$this->created),'order_id'=>$order,'reference'=>'recovery-'.$index,'subject'=>'alice','amount'=>100+$index,'created_at'=>$this->created,'tenant'=>Receiver\SCOPE,'topic'=>'order.created']);
    }
    public function delivery(string $body):string {return hash('sha256','recovery-delivery.'.$body);}
    public function request(int $index=1):SoSecurity\Webhook\Request
    {
        $body=$this->body($index);$id=$this->delivery($body);$time=(string)time();$key=Receiver\keyData($this->config['wire_keys']);$signature=base64_encode(hash_hmac('sha256',$id.'.'.$time.'.'.$body,$key['keys'][$key['current']],true));
        return new SoSecurity\Webhook\Request('POST',$this->config['url'],$body,['Webhook-Id'=>$id,'Webhook-Timestamp'=>$time,'Webhook-Signature'=>'v1,'.$signature]);
    }
    public function receive(int $index=1):array {return Receiver\receive($this->settings(),$this->request($index),static function():bool{return true;});}
    public function count():int {return (int)$this->pdo()->query('SELECT COUNT(*) FROM outbox_example_effects')->fetchColumn();}
    public function backup(string $name,bool $checkpoint=false):string
    {
        $handle=fopen($this->config['checkpoint_lock'],'rb');if(!flock($handle,LOCK_EX|LOCK_NB)){throw new RuntimeException('Test backup requires an idle receiver.');}
        try{$pdo=$this->pdo($checkpoint);Receiver\receiverIdle($pdo);Check::same('delete',strtolower($pdo->query('PRAGMA journal_mode')->fetchColumn()));$pdo=null;$target=$this->directory.'/'.$name.'.backup';Check::same(true,copy($this->config[$checkpoint?'checkpoint_database':'database'],$target));chmod($target,0600);return $target;}
        finally{flock($handle,LOCK_UN);fclose($handle);}
    }
    /** Caller releases its PDO references and stops child processes before restoring. */
    public function restore(string $backup,bool $checkpoint=false):void
    {
        $target=$this->config[$checkpoint?'checkpoint_database':'database'];$temporary=$target.'.restore';Check::same(true,copy($backup,$temporary));chmod($temporary,0600);Check::same(true,rename($temporary,$target));clearstatcache(true,$target);
    }
    public function close():void
    {
        foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->directory,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $path){if($path->isDir()){rmdir($path->getPathname());}else{unlink($path->getPathname());}}rmdir($this->directory);
    }
}
function recoveryCase(callable $work,bool $initialize=true):void
{
    $e=new ReceiverRecoveryEnvironment($initialize);try{$work($e);}finally{$e->close();}
}
function recoveryRefused(callable $work):void
{
    ++Check::$assertions;
    try{$work();}catch(SoSecurity\Exception\SecurityException $failure){Check::same('outbox_example.recovery_required',$failure->reason());return;}
    throw new RuntimeException('Expected controlled receiver recovery refusal.');
}
function recoveryPrepared(ReceiverRecoveryEnvironment $e,int $index=1):array
{
    $s=$e->settings();return Receiver\receiverLocked($s,static function()use($e,$s,$index):array{
        $body=$e->body($index);$plan=Receiver\receiverPlan($s,Receiver\receiverCurrent($s),$body,$e->delivery($body));Receiver\receiverSaveWitness($s,$plan,'prepared');return $plan;
    });
}
/** Kill an owned live child only after its explicit durable-stage marker; always reap it. */
function recoveryKill(ReceiverRecoveryEnvironment $e,string $phase,bool $cancel=false):void
{
    $bodyFile=$e->directory.'/child-body.json';file_put_contents($bodyFile,$e->body());chmod($bodyFile,0600);
    $command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/outbox-recovery-worker.php').' '.escapeshellarg($e->file).' '.escapeshellarg($phase).' '.escapeshellarg($bodyFile).($cancel?' cancel':'');
    $process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,null,['bypass_shell'=>true]);if(!is_resource($process)){throw new RuntimeException('Cannot start recovery test child.');}
    fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);$output='';$errors='';
    try{
        $deadline=microtime(true)+8;
        do{$output.=stream_get_contents($pipes[1]);$errors.=stream_get_contents($pipes[2]);$status=proc_get_status($process);if(strpos($output,"\n")!==false){break;}if(!$status['running']||strlen($output)>512||strlen($errors)>512){throw new RuntimeException('Recovery child failed before stage: '.$errors);}usleep(10000);}while(microtime(true)<$deadline);
        $marker=json_decode(trim($output),true);Check::same($phase,$marker['phase'] ?? null);Check::same(true,$status['running']);
        // POSIX exec makes proc_open's PID the PHP process rather than a surviving shell.
        Check::same($status['pid'],$marker['pid'] ?? null);Check::same(true,proc_terminate($process,9));
        $deadline=microtime(true)+4;do{$status=proc_get_status($process);if(!$status['running']){break;}usleep(10000);}while(microtime(true)<$deadline);
        Check::same(false,$status['running']);Check::same(true,$status['signaled']);Check::same(9,$status['termsig']);Check::same('',$errors.stream_get_contents($pipes[2]));
    }finally{if(proc_get_status($process)['running']){proc_terminate($process,9);}fclose($pipes[1]);fclose($pipes[2]);proc_close($process);}
}
