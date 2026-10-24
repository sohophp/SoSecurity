<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Mfa\ManagedFactorFrame;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Mfa\TotpFactorState;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;

/** Fixed approved destruction of at most four reviewed coordinates. No activation or arbitrary work callback. */
final class StateFactorContainment
{
    private $dependencies;
    private $fingerprint;
    private $execution;
    public function __construct(LocalStateWitness $witness,StateFactorInventory $inventory,CompositeStateSnapshot $source,FileStateSnapshot $files,string $fileName,TotpFactors $factors,string $site,string $scope,string $epoch,HmacKeys $keys,string $subject,array $positions,callable $persist,string $mode='managed')
    {
        $context=$inventory->containmentContext($witness,$source,$files,$factors,$site,$scope,$epoch,$keys);Guard::label($subject);
        if($context===null||!$inventory->boundTo($witness)||!$witness->coversSnapshot($source)||!$source->contains($fileName,$files)||$witness->format()!==3||preg_match('//u',$subject)!==1||count($positions)<1||count($positions)>4||!in_array($mode,['managed','legacy_and_managed'],true)){self::invalid();}
        $copy=[];foreach($positions as $position){if(!is_int($position)||$position<1||$position>1000000||in_array($position,$copy,true)){self::invalid();}$copy[]=$position;}sort($copy,SORT_NUMERIC);
        $this->fingerprint=hash('sha256',json_encode(['SoSecurity.Account.StateFactorContainment.1',$witness->binding(),$witness->generation(),$inventory->binding(),$source->fingerprint(),$files->fingerprint(),$fileName,$site,$scope,$epoch,$keys->currentId(),$subject,$copy,$mode],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        $this->dependencies=static function()use($witness,$inventory,$source,$files,$fileName,$factors,$keys,$subject,$copy,$context,$persist,$mode):array{return [$witness,$inventory,$source,$files,$fileName,$factors,$keys,$subject,$copy,$context['context'],$context['clock'],$persist,$mode,$context['reference']];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use an exact covered fixed factor destruction plan with at most four coordinates.','configuration.factor_containment');}
    private function d():array{return ($this->dependencies)();}
    public function binding():string{return $this->fingerprint;}
    public function count():int{return count($this->d()[8]);}
    public function description():array{$d=$this->d();return ['subject'=>$d[7],'positions'=>$d[8],'mode'=>$d[12]];}
    public function boundTo(LocalStateWitness $witness):bool{$d=$this->d();return $d[0]===$witness&&$d[1]->boundTo($witness)&&$witness->coversSnapshot($d[2]);}
    public function usesFactors(TotpFactors $factors):bool{return $this->d()[5]===$factors;}
    public function usesContext(string $context,HmacKeys $keys):bool{$d=$this->d();return $d[9]===$context&&$d[6]===$keys;}
    private function target(string $key,?string $raw):string
    {
        $d=$this->d();$migration=null;
        if($raw!==null){
            $outer=json_decode($raw,true,32);if(!is_array($outer)||array_keys($outer)!==['expires','value']||$outer['expires']!==0||!is_array($outer['value'])){throw new StorageException('A present factor container must be bounded, permanent and structurally valid.','account.factor_container');}
            $value=$outer['value'];
            if(($value['v']??null)===1&&$d[12]==='legacy_and_managed'){TotpFactorState::read($value,$d[10]->now());}
            else{$frame=ManagedFactorFrame::read($d[9],$d[6],$key,$value);$migration=$frame['migration'];}
        }
        $value=['v'=>$migration===null?2:3,'context'=>$d[9],'key'=>$d[6]->currentId(),'payload'=>null];if($migration!==null){$value['migration']=$migration;}$value['seal']=bin2hex($d[6]->sign('SoSecurity.Mfa.ManagedFactor.1.'.$key.':'.ManagedFactorFrame::encode($value)));return Codec::encode(new Change($value,0,true));
    }
    private function view():array
    {
        $d=$this->d();$deadline=new Deadline(30000);$cursor=null;$digest=null;$chosen=[];$found=[];$wanted=$d[8];
        do{
            $page=$d[1]->page($d[7],$cursor);if($digest!==null&&$digest!==$page['observed']){throw new StorageException('Factor inventory changed during exact selection.','account.containment_changed');}$digest=$page['observed'];
            if($wanted[count($wanted)-1]>$page['total']){throw new StorageException('A selected factor coordinate is missing.','account.containment_changed');}
            foreach($page['slots'] as $slot){if(in_array($slot['position'],$wanted,true)){$chosen[$slot['file']]=$slot;$found[$slot['position']]=true;}}$cursor=$page['cursor'];$deadline->check('account.snapshot_timeout');
        }while($page['more']&&$cursor['offset']<$wanted[count($wanted)-1]);
        if(count($found)!==count($wanted)){self::invalid();}$selectors=[];foreach(array_values($chosen) as $index=>$slot){$selectors['factor_'.$index]=$slot['file'];}
        if(count($selectors)<1||count($selectors)>4){self::invalid();}$view=$d[2]->capture([$d[4]=>$selectors]);$part=$view->part($d[4]);if(!$view->matches($d[2])||!$part instanceof FileStateCapture||!$part->matches($d[3])||$view->digest()!==$digest){throw new StorageException('Exact factor bytes differ from the reviewed inventory.','account.containment_changed');}
        $entries=[];foreach(array_values($chosen) as $i=>$slot){$key=Guard::key('mfa-totp',$slot['scope'],$slot['subject']);$reference=$d[5]->stateReference($slot['scope'],$slot['subject'],$d[9]);if($reference===null||$reference['file']!==$slot['file']||!$d[3]->coversReference($reference)){self::invalid();}$raw=$part->file('factor_'.$i);$entries[$key]=['slot'=>$slot,'reference'=>$reference,'old'=>$raw,'new'=>$this->target($key,$raw)];}return [$digest,$entries];
    }
    private function physicalManifest(array $entries):array
    {
        $d=$this->d();$items=[];foreach($entries as $key=>$entry){$items[]=['key'=>$key,'file'=>$entry['reference']['file'],'before'=>$entry['old']===null?null:hash('sha256',$entry['old']),'after'=>$entry['new']];}
        $manifest=['format'=>1,'source'=>$d[2]->fingerprint(),'files'=>$d[3]->fingerprint(),'name'=>$d[4],'factor'=>$d[13],'context'=>$d[9],'entries'=>$items];if(!StateFactorManifest::valid($manifest)){self::invalid();}return $manifest;
    }
    /** No old secret bytes are exported or persisted in this physical effect description. */
    public function prepared():array{if($this->execution!==null){self::invalid();}$view=$this->view();return ['observed'=>$view[0],'manifest'=>$this->physicalManifest($view[1])];}
    public function observed():string{if($this->execution!==null){self::invalid();}return $this->view()[0];}
    public function guard(LocalStateWitness $witness,string $operation):void{if(!$this->boundTo($witness)||!$witness->factorContainmentActive($this,$operation)){self::invalid();}$this->executionDeadline($operation);$witness->factorContainmentCurrent($this,$operation);$this->executionDeadline($operation);}
    private function executionDeadline(string $operation):void{if($this->execution!==null){$v=($this->execution)();if($v[0]!==$operation){self::invalid();}$v[2]->check('account.witness_timeout');}}
    private function entry(LocalStateWitness $witness,string $operation,FileStore $store,string $key):array
    {
        $this->guard($witness,$operation);if($this->execution===null){self::invalid();}$v=($this->execution)();if($v[0]!==$operation||!isset($v[1][$key])||$v[1][$key]['reference']!==$store->snapshotReference($key)){self::invalid();}return $v[1][$key];
    }
    /** Raw CAS input and fixed output; caller-supplied payloads or callbacks are never accepted. */
    public function replacement(LocalStateWitness $witness,string $operation,FileStore $store,string $key,?string $raw):string
    {
        $entry=$this->entry($witness,$operation,$store,$key);if($entry['old']!==$raw){throw new StorageException('Exact factor bytes changed before destruction.','account.factor_cas');}return $entry['new'];
    }
    /** Trusted platform fsync acknowledgement only. False/exception always keeps the witness quarantined. */
    public function persist(LocalStateWitness $witness,string $operation,FileStore $store,string $key,$handle):void
    {
        $this->entry($witness,$operation,$store,$key);if(!is_resource($handle)||($this->d()[11])($handle)!==true){throw new StorageException('Factor persistence was not acknowledged.','account.factor_persistence');}$this->guard($witness,$operation);
    }
    public function apply(LocalStateWitness $witness,string $operation,Deadline $deadline):void
    {
        if($this->execution!==null){self::invalid();}$this->guard($witness,$operation);$view=$this->view();if(!$witness->factorContainmentActive($this,$operation,$view[0])){throw new StorageException('Selected factor source changed before effects.','account.containment_changed');}$entries=$view[1];if(!$witness->factorContainmentManifest($this,$operation,$this->physicalManifest($entries))){throw new StorageException('Persisted physical effect manifest differs from the selected bytes.','account.containment_changed');}$this->execution=static function()use($operation,$entries,$deadline):array{return [$operation,$entries,$deadline];};
        foreach($entries as $entry){$deadline->check('account.witness_timeout');$slot=$entry['slot'];$this->d()[5]->containState($slot['scope'],$slot['subject'],$this,$witness,$operation);}
    }
    public function contained(string $operation):string
    {
        $d=$this->d();$this->guard($d[0],$operation);if($this->execution===null){self::invalid();}$v=($this->execution)();if($v[0]!==$operation){self::invalid();}$selectors=[];foreach($v[1] as $entry){$selectors['factor_'.count($selectors)]=$entry['slot']['file'];}$view=$d[2]->capture([$d[4]=>$selectors]);$part=$view->part($d[4]);if(!$view->matches($d[2])||!$part instanceof FileStateCapture||!$part->matches($d[3])){self::invalid();}
        foreach(array_values($v[1]) as $i=>$entry){if($part->file('factor_'.$i)!==$entry['new']){throw new StorageException('Permanent factor destruction postcondition changed.','account.containment_changed');}}return $view->digest();
    }
    public function __debugInfo():array{return ['factor_containment'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
