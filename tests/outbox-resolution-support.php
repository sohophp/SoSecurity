<?php
declare(strict_types=1);
require_once __DIR__.'/outbox-recovery-support.php';
require_once __DIR__.'/webhook-inbox-support.php';
use SoSecurity\Examples\Outbox as Resolution;

function nativeResolutionSettings(string $file):array
{
    $old=getenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$file);
    try{return Resolution\settings('sender');}finally{if($old===false){putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');}else{putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$old);}}
}
final class NativeResolutionEnvironment
{
    public $receiver;
    public $config;
    public $file;
    public $body;
    public $id;
    public $delivery;
    public function __construct()
    {
        $this->receiver=new ReceiverRecoveryEnvironment();$r=$this->receiver;$d=$r->directory;$r->created=time()-3;
        $r->pdo()->exec("UPDATE outbox_example_actors SET roles='[\"receiver_worker\",\"receiver_admin\",\"receiver_reconciler\"]'");
        recoveryJson($d.'/resolution-seeds.json',['current'=>'old','keys'=>['old'=>base64_encode(str_repeat('q',32))]]);$r->configure(['resolution_keys'=>$d.'/resolution-seeds.json']);
        recoveryJson($d.'/resolution-public.json',Resolution\resolutionPublicKeys($r->settings()));
        mkdir($d.'/sender-state',0700);$pdo=new PDO('sqlite:'.$d.'/sender.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);chmod($d.'/sender.sqlite',0600);
        foreach(['outbox-sqlite','idempotency-sqlite','outbox-example-sender-sqlite'] as $name){$pdo->exec(file_get_contents(dirname(__DIR__).'/resources/sql/'.$name.'.sql'));}
        $pdo->exec("INSERT INTO outbox_example_actors VALUES('alice','1',1,'[\"orders_writer\",\"outbox_worker\",\"outbox_admin\",\"outbox_reconciler\"]')");
        foreach(['sender-seals'=>'t','sender-idempotency'=>'i'] as $name=>$byte){recoveryJson($d.'/'.$name.'.json',['current'=>'old','keys'=>['old'=>base64_encode(str_repeat($byte,32))]]);}
        $this->config=['role'=>'sender','document_root'=>$d.'/web','database'=>$d.'/sender.sqlite','storage'=>$d.'/sender-state','actor'=>'alice','version'=>'1','epoch'=>str_repeat('a',64),'seals'=>$d.'/sender-seals.json','wire_keys'=>$r->config['wire_keys'],'idempotency_keys'=>$d.'/sender-idempotency.json','url'=>$r->config['url'],'resolution_keys'=>$d.'/resolution-public.json','receiver_epoch'=>$r->config['epoch'],'policy'=>['message_age'=>1,'recovery_age'=>1,'retention_seconds'=>0]];
        $this->file=$d.'/sender.json';$this->configure([]);$s=$this->settings();$this->body=$r->body();$data=Resolution\event($this->body);$this->id=$data['event_id'];$this->delivery=Resolution\resolutionDelivery($this->id);
        // Only fixture creation uses a past clock; reconciliation and signed evidence use the actual current clock.
        $clock=new TestClock();$clock->time=$r->created;$queue=new SoSecurity\Outbox\SqlOutbox($pdo,Resolution\SITE,$s['epoch'],Resolution\sealingKeys($s['seals']),static function():bool{return true;},new SoSecurity\Outbox\Policy($s['policy']),$clock,static function():bool{return true;});
        $queue->initialize(Resolution\SCOPE,Resolution\PRODUCER,'alice');$pdo->exec('BEGIN IMMEDIATE');
        try{
            $q=$pdo->prepare('INSERT INTO outbox_example_orders VALUES(:subject,:reference,:order,:amount,:created,:event,:body)');foreach(['subject'=>$data['subject'],'reference'=>$data['reference'],'order'=>$data['order_id'],'amount'=>$data['amount'],'created'=>$data['created_at'],'event'=>$data['event_id']] as $key=>$value){$q->bindValue(':'.$key,$value,is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR);}$q->bindValue(':body',$this->body,PDO::PARAM_LOB);$q->execute();$q->closeCursor();$queue->enqueue(Resolution\message($data,$this->body),'alice');$pdo->exec('COMMIT');
        }catch(Throwable $error){$pdo->exec('ROLLBACK');throw $error;}
        Check::same(1,Resolution\outbox($s)->maintain(Resolution\SCOPE,Resolution\PRODUCER,'alice')['retired']);Check::same(true,Resolution\resolutionInitialize($s));
    }
    public function configure(array $changes):void {$this->config=array_replace($this->config,$changes);recoveryJson($this->file,$this->config);}
    public function settings():array {return nativeResolutionSettings($this->file);}
    public function pdo():PDO {return new PDO('sqlite:'.$this->config['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);}
    public function request():string {return Resolution\resolutionExport($this->settings(),$this->id);}
    public function proof(bool $cancel=true):string {return Resolution\resolutionTerminal($this->receiver->settings(),$this->request(),$cancel);}
    public function receive():array
    {
        $stamp=(string)time();$keys=Resolution\keyData($this->receiver->config['wire_keys']);$signature=base64_encode(hash_hmac('sha256',$this->delivery.'.'.$stamp.'.'.$this->body,$keys['keys'][$keys['current']],true));
        return Resolution\receive($this->receiver->settings(),new SoSecurity\Webhook\Request('POST',$this->config['url'],$this->body,['Webhook-Id'=>$this->delivery,'Webhook-Timestamp'=>$stamp,'Webhook-Signature'=>'v1,'.$signature]),static function():bool{return true;});
    }
    public function close():void {$this->receiver->close();}
}
function nativeResolutionCase(callable $work):void {$e=new NativeResolutionEnvironment();try{$work($e);}finally{$e->close();}}
function nativeResolutionRefused(callable $work):void {Check::throws(SoSecurity\Exception\SecurityException::class,$work);}
function nativeResolutionAlter(NativeResolutionEnvironment $e,string $proof,array $changes):string
{
    $envelope=json_decode($proof,true);$payload=json_decode(base64_decode($envelope['payload'],true),true);$payload=json_encode(array_replace($payload,$changes));$keys=Resolution\keyData($e->receiver->config['resolution_keys']);$secret=sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($keys['keys'][$keys['current']]));
    return json_encode(['payload'=>base64_encode($payload),'key_id'=>$keys['current'],'signature'=>base64_encode(sodium_crypto_sign_detached('SoSecurity.OutboxExample.TerminalReceipt.1.'.$payload,$secret))]);
}
function nativeResolutionCli(string $config,string $entry,array $arguments):array
{
    $old=getenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$config);$command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(dirname(__DIR__).'/examples/'.$entry.'.php');foreach($arguments as $argument){$command.=' '.escapeshellarg($argument);}
    try{$process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start owned CLI test.');}fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$error=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$code=proc_close($process);return ['code'=>$code,'output'=>$output,'error'=>$error];}
    finally{if($old===false){putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG');}else{putenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG='.$old);}}
}
function nativeResolutionKill(NativeResolutionEnvironment $e,string $proof,string $phase,bool $archive=false):void
{
    $file=$e->receiver->directory.'/kill-proof.json';file_put_contents($file,$proof);chmod($file,0600);$command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/outbox-resolution-worker.php').' '.escapeshellarg($e->file).' '.escapeshellarg($file).' '.escapeshellarg($phase).($archive?' archive':'');
    $process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);if(!is_resource($process)){throw new RuntimeException('Cannot start owned resolution child.');}fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);$output='';$errors='';
    try{
        $deadline=microtime(true)+8;do{$output.=stream_get_contents($pipes[1]);$errors.=stream_get_contents($pipes[2]);$status=proc_get_status($process);if(strpos($output,"\n")!==false){break;}if(!$status['running']||strlen($output)>512||strlen($errors)>512){throw new RuntimeException('Resolution child failed before its marker.');}usleep(10000);}while(microtime(true)<$deadline);
        $marker=json_decode(trim($output),true);Check::same($phase,$marker['phase'] ?? null);Check::same(true,$status['running']);Check::same($status['pid'],$marker['pid'] ?? null);Check::same(true,proc_terminate($process,9));
        $deadline=microtime(true)+4;do{$status=proc_get_status($process);if(!$status['running']){break;}usleep(10000);}while(microtime(true)<$deadline);Check::same(false,$status['running']);Check::same(true,$status['signaled']);Check::same(9,$status['termsig']);Check::same('',$errors.stream_get_contents($pipes[2]));
    }finally{if(proc_get_status($process)['running']){proc_terminate($process,9);}fclose($pipes[1]);fclose($pipes[2]);proc_close($process);}
}
