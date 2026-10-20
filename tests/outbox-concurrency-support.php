<?php
declare(strict_types=1);

/** Test-owned child only. Bounded pipes/waits and explicit reaping also cover failed assertions. */
final class OutboxTestProcess
{
    private $process;
    private $pipes=[];
    private $exit;
    private $started;
    private $output='';
    private $errors='';
    public function __construct(array $configuration)
    {
        $this->started=microtime(true);
        $command='exec '.escapeshellarg(PHP_BINARY).' '.escapeshellarg(__DIR__.'/outbox-worker.php');
        $this->process=proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$this->pipes,null,null,['bypass_shell'=>true]);
        if(!is_resource($this->process)){throw new RuntimeException('Cannot launch private Outbox worker.');}
        try{
            $input=json_encode($configuration);
            if(!is_string($input)||fwrite($this->pipes[0],$input)!==strlen($input)){throw new RuntimeException('Cannot supply private Outbox test data.');}
            fclose($this->pipes[0]);unset($this->pipes[0]);
            stream_set_blocking($this->pipes[1],false);stream_set_blocking($this->pipes[2],false);
        }catch(Throwable $error){$this->close();throw $error;}
    }
    public function running():bool
    {
        if(!is_resource($this->process)){return false;}
        $status=proc_get_status($this->process);
        if(!$status['running']&&$this->exit===null){$this->exit=$status['exitcode'];}
        return $status['running'];
    }
    private function read():void
    {
        $this->output.=stream_get_contents($this->pipes[1],65537-strlen($this->output));$this->errors.=stream_get_contents($this->pipes[2],16385-strlen($this->errors));
        if(strlen($this->output)>65536||strlen($this->errors)>16384){throw new RuntimeException('Outbox test worker output exceeds its bound.');}
    }
    public function result():array
    {
        try{
            do{
                $running=$this->running();$this->read();
                if(microtime(true)-$this->started>45){throw new RuntimeException('Outbox test worker timeout.');}
                if($running){usleep(10000);}
            }while($running);
            $this->read();$exit=$this->exit;$this->close();
            if($exit!==0||$this->errors!==''){throw new RuntimeException('Outbox test worker failed: '.(string)$exit.' '.$this->errors);}
            $result=json_decode($this->output,true,16);
            if(!is_array($result)){throw new RuntimeException('Invalid Outbox worker result.');}return $result;
        }finally{$this->close();}
    }
    public function kill():bool {return $this->running()&&proc_terminate($this->process,9);}
    public function close():void
    {
        if(!is_resource($this->process)){return;}
        if($this->running()){proc_terminate($this->process,9);}
        foreach($this->pipes as $pipe){if(is_resource($pipe)){fclose($pipe);}}
        proc_close($this->process);$this->process=null;$this->pipes=[];
    }
}

function outboxWorkerResult(array $configuration):array
{
    $process=new OutboxTestProcess($configuration);return $process->result();
}
function outboxParallel(array $configuration,string $directory,?callable $change=null):array
{
    $start=$directory.'/start-'.bin2hex(random_bytes(8));$workers=[];
    try{
        for($i=0;$i<24;++$i){
            $input=$change===null?$configuration:$change($configuration,$i);$input['start']=$start;
            $workers[]=new OutboxTestProcess($input);
        }
        if(file_put_contents($start,'go')!==2||!chmod($start,0600)){throw new RuntimeException('Cannot release private Outbox workers.');}
        $results=[];foreach($workers as $worker){$results[]=$worker->result();}return $results;
    }finally{foreach($workers as $worker){$worker->close();}if(is_file($start)){unlink($start);}}
}
/** Pause a known live child, inspect through an independent connection, then SIGKILL and reap it. */
function outboxKillAt(array $configuration,callable $observe):array
{
    $worker=new OutboxTestProcess($configuration);
    try{
        $until=microtime(true)+15;
        while(!is_file($configuration['checkpoint'])&&microtime(true)<$until){
            if(!$worker->running()){$worker->result();throw new RuntimeException('Outbox checkpoint worker exited early.');}usleep(10000);
        }
        Check::same(true,is_file($configuration['checkpoint']));Check::same(true,$worker->running());
        $data=json_decode(file_get_contents($configuration['checkpoint']),true,8);
        if(!is_array($data)){throw new RuntimeException('Invalid private Outbox checkpoint.');}
        $observe($data);Check::same(true,$worker->running());Check::same(true,$worker->kill());return $data;
    }finally{$worker->close();if(is_file($configuration['checkpoint'])){unlink($configuration['checkpoint']);}}
}
