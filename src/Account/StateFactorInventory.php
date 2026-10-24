<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;

/** Read-only inventory of exact directory and retained workflow coordinates. Data is never a cleanup capability. */
final class StateFactorInventory
{
    private $dependencies;
    private $fingerprint;
    public function __construct(LocalStateWitness $witness,CompositeStateSnapshot $source,SqlStateSnapshot $sql,FileStateSnapshot $files,string $sqlName,string $fileName,FactorRegistry $registry,TotpFactors $factors,FactorOperations $operations,FactorRestoration $restoration,FactorRecovery $recovery,FactorMigration $migration,string $site,string $scope,string $epoch,HmacKeys $keys,Clock $clock,int $milliseconds=30000)
    {
        new Deadline($milliseconds);$directory=$registry->ledgerPolicy($keys);$factor=$factors->statePolicy($site,$scope,$epoch,$keys);$services=[$operations,$restoration,$recovery,$migration];$contexts=[];
        foreach($services as $service){$v=$service->stateHistory($sql->connection(),$factors,$site,$scope,$epoch,$keys,$clock);if($v===null){self::invalid();}$contexts[]=$v;}
        $history=$contexts[0];foreach($contexts as $v){$a=$v;$b=$history;unset($a['owner_prefix'],$b['owner_prefix']);if($a!==$b){self::invalid();}}
        $types=Ledger::recordTypes();$types['payload']='blob:16384';
        if($witness->format()!==3||!$witness->matches($site,$scope,$epoch)||!$witness->coversSnapshot($source)||!$source->contains($sqlName,$sql)||!$source->contains($fileName,$files)||$sqlName===$fileName||$directory===null||$factor===null||!$files->coversReference($factor['reference'])||!($factor['clock']===$clock||($factor['clock'] instanceof \SoSecurity\Support\SystemClock&&$clock instanceof \SoSecurity\Support\SystemClock))||!$registry->matchesStatePolicy($factors,$sql->connection(),$site,$scope,$epoch,$clock)||!$sql->containsDefinition('sosecurity_account_roots',Ledger::rootTypes(),['namespace'],[])||!$sql->containsDefinition('sosecurity_account_records',$types,['namespace','record_id'],[])){self::invalid();}
        $this->fingerprint=hash('sha256',json_encode(['SoSecurity.Account.StateFactorInventory.2',$witness->binding(),$witness->generation(),$source->fingerprint(),$sql->fingerprint(),$files->fingerprint(),$sqlName,$fileName,$site,$scope,$epoch,$directory->fingerprint(),$factor['context'],$factor['reference'],$contexts],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        $this->dependencies=static function()use($witness,$source,$sql,$files,$sqlName,$registry,$factors,$services,$site,$scope,$epoch,$keys,$clock,$directory,$factor,$contexts,$history,$milliseconds):array{return [$witness,$source,$sql,$files,$sqlName,$registry,$factors,$services,$site,$scope,$epoch,$keys,$clock,$directory,$factor['context'],$contexts,$history,$milliseconds];};
        $sql->selections($this->selectors($history['namespace'],null,7));
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use the exact covered managed directory and all four matching workflow services.','configuration.factor_inventory');}
    /** @return never */
    private static function corrupt():void{throw new StorageException('Factor inventory history is incomplete or changed.','account.inventory_changed');}
    private function d():array{return ($this->dependencies)();}
    /** @internal Exact read-only component binding for fixed physical containment. */
    public function containmentContext(LocalStateWitness $witness,CompositeStateSnapshot $source,FileStateSnapshot $files,TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys):?array
    {
        $d=$this->d();foreach($d[7] as $service){if(!$service->recoveryBoundary($witness)){return null;}}return $d[0]===$witness&&$d[1]===$source&&$d[3]===$files&&$d[6]===$factors&&$d[8]===$site&&$d[9]===$scope&&$d[10]===$epoch&&$d[11]===$keys?['context'=>$d[14],'clock'=>$d[12],'reference'=>$d[6]->statePolicy($site,$scope,$epoch,$keys)['reference']]:null;
    }
    public function binding():string{return $this->fingerprint;}
    public function boundTo(LocalStateWitness $witness):bool{$d=$this->d();return $d[0]===$witness&&$witness->coversSnapshot($d[1]);}
    private function selectors(string $namespace,?array $after,int $limit):array
    {
        return ['root'=>['table'=>'sosecurity_account_roots','key'=>['namespace'=>$namespace],'columns'=>array_keys(Ledger::rootTypes())],
            'records'=>['table'=>'sosecurity_account_records','key'=>['namespace'=>$namespace],'columns'=>array_keys(Ledger::recordTypes()),'page'=>true,'maximum'=>$limit,'after'=>$after]];
    }
    private function capture(array $selectors,?string &$digest,Deadline $deadline):SqlStateCapture
    {
        $deadline->check('account.snapshot_timeout');$d=$this->d();$view=$d[1]->capture([$d[4]=>$selectors]);$part=$view->part($d[4]);if(!$view->matches($d[1])||!$part instanceof SqlStateCapture||!$part->matches($d[2])){self::invalid();}
        if($digest!==null&&!hash_equals($digest,$view->digest())){self::corrupt();}$digest=$view->digest();$deadline->check('account.snapshot_timeout');return $part;
    }
    private function record(array $row,string $namespace,string $policy,int $format,int $maximum,int $now):array
    {
        $d=$this->d();$payload=$row['payload'];unset($row['payload']);$row['body_length']=strlen($payload);$row=LedgerState::authenticate($row,false,$namespace,$d[10],$policy,$format,$maximum,$d[11],$now);$row['payload']=LedgerState::payload($row,$payload);return $row;
    }
    private function item(array &$selected,int &$ordinal,int $offset,int $maximum,array $slot,string $origin,string $record):void
    {
        ++$ordinal;if($ordinal<=$offset||count($selected)>=$maximum){return;}$d=$this->d();$reference=$d[6]->stateReference($slot['scope'],$slot['subject'],$d[14]);if($reference===null||!$d[3]->coversReference($reference)){self::invalid();}
        $selected[]=['position'=>$ordinal,'origin'=>$origin,'record'=>$record,'scope'=>$slot['scope'],'subject'=>$slot['subject'],'factor'=>$slot['factor'],'file'=>$reference['file']];
    }
    /** Stable ordinal pages include historical/cleaned/pending coordinates; duplicates retain distinct evidence. */
    /** @return array{observed:string,binding:string,subject:string,slots:array<int,array{position:int,origin:string,record:string,scope:string,subject:string,factor:?string,file:string}>,total:int,more:bool,cursor:array{binding:string,offset:int}} */
    public function page(string $subject,?array $after=null,int $maximum=8):array
    {
        Guard::label($subject);if(preg_match('//u',$subject)!==1||$maximum<1||$maximum>8){self::invalid();}$offset=0;
        if($after!==null){if(array_keys($after)!==['binding','offset']||!is_string($after['binding'])||preg_match('/\A[a-f0-9]{64}\z/D',$after['binding'])!==1||!is_int($after['offset'])||$after['offset']<0||$after['offset']>1000000){self::invalid();}$offset=$after['offset'];}
        $d=$this->d();$now=$d[12]->now();if($now<0||$now>PHP_INT_MAX-31536001){throw new StorageException('Invalid inventory clock.','account.clock');}$deadline=new Deadline($d[17]);$digest=null;$selected=[];$ordinal=0;
        $namespace=hash('sha256',json_encode(['SoSecurity.Account.Ledger.1','account-factor-directory:'.hash('sha256',json_encode([$d[8],$subject])),$d[9],$d[10]],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        $view=$this->capture($this->selectors($namespace,null,1),$digest,$deadline);$root=$view->row('root');$page=$view->page('records');if($root===null||$page['total']!==1||count($page['rows'])!==1||$page['more']){self::corrupt();}
        $root=LedgerState::authenticate($root,true,$namespace,$d[10],$d[13]->fingerprint(),1,$d[13]->maximumEntries(),$d[11],$now);$row=$this->record($page['rows'][0],$namespace,$d[13]->fingerprint(),1,$d[13]->maximumEntries(),$now);LedgerState::single($root,$row,1);$directory=FactorDirectoryState::read($d[8],$d[9],$d[10],$row,$subject);
        $binding=hash('sha256','SoSecurity.Account.StateFactorInventory.Cursor.1.'.$this->fingerprint.$digest.json_encode($subject));if($after!==null&&!hash_equals($binding,$after['binding'])){throw new StorageException('Inventory cursor belongs to another observation or account.','account.inventory_cursor');}
        // The fixed legacy coordinate is included even after a pointer moved; hashed filenames cannot reveal it later.
        $this->item($selected,$ordinal,$offset,$maximum,['scope'=>$d[9],'subject'=>$subject,'factor'=>null],'legacy','');
        if($directory['factor_id']!==''){$this->item($selected,$ordinal,$offset,$maximum,['scope'=>$directory['slot_scope'],'subject'=>$directory['slot_subject'],'factor'=>$directory['factor_id']],'directory',$row['record_id']);}
        $history=$d[16];$cursor=null;$seen=0;$hash=hash_init('sha256');hash_update($hash,'SoSecurity.Account.History.1.'.$history['namespace']);$historyRoot=null;$references=[];
        do{
            $view=$this->capture($this->selectors($history['namespace'],$cursor,7),$digest,$deadline);$raw=$view->row('root');$page=$view->page('records');
            if($raw===null){if($page['total']!==0){self::corrupt();}break;}
            $raw=LedgerState::authenticate($raw,true,$history['namespace'],$d[10],$history['policy'],$history['format'],$history['maximum'],$d[11],$now);if($historyRoot!==null&&$historyRoot!==$raw){self::corrupt();}$historyRoot=$raw;
            if($page['total']!==$raw['entries']){self::corrupt();}
            foreach($page['rows'] as $row){$row=$this->record($row,$history['namespace'],$history['policy'],$history['format'],$history['maximum'],$now);hash_update($hash,$row['record_id'].$row['seal']);++$seen;
                foreach($d[15] as $index=>$context){if($row['owner']!==hash('sha256',$context['owner_prefix'].$subject)){continue;}$parsed=$d[7][$index]->stateSlots($row,$subject);
                    foreach($parsed['slots'] as $slot){$this->item($selected,$ordinal,$offset,$maximum,$slot,['management','restoration','recovery','migration'][$index],$row['record_id']);}
                    if($parsed['reference']!==null){if(isset($references[$index])){self::corrupt();}$references[$index]=['record'=>$parsed['reference'],'owner'=>$row['owner']];}
                }
            }
            $cursor=$page['cursor'];$deadline->check('account.snapshot_timeout');
        }while($page['more']);
        if($historyRoot!==null&&($seen!==$historyRoot['entries']||!hash_equals($historyRoot['history_digest'],hash_final($hash)))){self::corrupt();}
        if($references!==[]){$selectors=[];foreach($references as $index=>$reference){$selectors['reference_'.$index]=['table'=>'sosecurity_account_records','key'=>['namespace'=>$history['namespace'],'record_id'=>$reference['record']],'columns'=>array_keys(Ledger::recordTypes())];}$view=$this->capture($selectors,$digest,$deadline);
            foreach($references as $index=>$reference){$row=$view->row('reference_'.$index);if($row===null||$row['owner']!==$reference['owner']||$row['kind']!=='recover'){self::corrupt();}$row=$this->record($row,$history['namespace'],$history['policy'],$history['format'],$history['maximum'],$now);$d[7][$index]->stateSlots($row,$subject);}
        }
        if($offset>$ordinal){throw new StorageException('Inventory cursor exceeds the complete retained inventory.','account.inventory_cursor');}$next=$selected===[]?$offset:$selected[count($selected)-1]['position'];
        return ['observed'=>$digest,'binding'=>$this->fingerprint,'subject'=>$subject,'slots'=>$selected,'total'=>$ordinal,'more'=>$next<$ordinal,'cursor'=>['binding'=>$binding,'offset'=>$next]];
    }
    public function __debugInfo():array{return ['factor_inventory'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
