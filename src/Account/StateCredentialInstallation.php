<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\Change;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Mfa\ManagedFactorFrame;
use SoSecurity\Password\HashBudget;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SqlTransaction;

/** Fixed new/retired factor and session files then atomic account/directory installation. Never activation or arbitrary SQL/callback execution. */
final class StateCredentialInstallation
{
    private $dependencies;
    private $image;
    private $packet;
    private $fingerprint;
    private $initial=false;
    private $execution;
    private function __construct(LocalStateWitness $w,CompositeStateSnapshot $source,SqlStateSnapshot $sql,FileStateSnapshot $files,string $sqlName,string $fileName,StateAccountContainment $accounts,StateRecoveryCredentials $credentials,FactorRegistry $registry,TotpFactors $factors,HmacKeys $keys,string $site,string $scope,string $epoch,Clock $clock,callable $persist,?\SoSecurity\Auth\SessionRegistry $sessions=null,?FileStore $sessionStore=null)
    {
        if(!$w->coversSnapshot($source)||!$source->contains($sqlName,$sql)||!$source->contains($fileName,$files)||!$accounts->boundTo($w)||!$w->usesKeys($keys)||!$w->matches($site,$scope,$epoch)||!$credentials->matchesInstallation($factors,$keys,$site,$scope,$epoch)||!$registry->matchesStatePolicy($factors,$sql->connection(),$site,$scope,$epoch,$clock)||$registry->ledgerPolicy($keys)===null||$factors->statePolicy($site,$scope,$epoch,$keys)===null){self::invalid();}
        if(($sessions===null)!==($sessionStore===null)){self::invalid();}
        $recordTypes=Ledger::recordTypes();$recordTypes['payload']='blob:16384';if(!$sql->coversColumns('sosecurity_account_roots',Ledger::rootTypes(),['namespace'],[])||!$sql->coversColumns('sosecurity_account_records',$recordTypes,['namespace','record_id'],[])){self::invalid();}
        $this->dependencies=static function()use($w,$source,$sql,$files,$sqlName,$fileName,$accounts,$credentials,$registry,$factors,$keys,$site,$scope,$epoch,$clock,$persist,$sessions,$sessionStore):array{return [$w,$source,$sql,$files,$sqlName,$fileName,$accounts,$credentials,$registry,$factors,$keys,$site,$scope,$epoch,$clock,$persist,$sessions,$sessionStore];};
    }
    public static function prepare(LocalStateWitness $w,CompositeStateSnapshot $source,SqlStateSnapshot $sql,FileStateSnapshot $files,string $sqlName,string $fileName,StateAccountContainment $accounts,StateRecoveryCredentials $credentials,FactorRegistry $registry,TotpFactors $factors,HmacKeys $keys,string $site,string $scope,string $epoch,Clock $clock,callable $persist,array $accountManifest,string $subject,string $selector,callable $budget,?\SoSecurity\Auth\SessionRegistry $sessions=null,?FileStore $sessionStore=null):self
    {
        $self=new self($w,$source,$sql,$files,$sqlName,$fileName,$accounts,$credentials,$registry,$factors,$keys,$site,$scope,$epoch,$clock,$persist,$sessions,$sessionStore);$record=$credentials->installationRecord($w,$accounts,$accountManifest,$subject,$selector,$budget);$self->prepareRecord($record);$self->initial=true;return $self;
    }
    public static function resume(LocalStateWitness $w,CompositeStateSnapshot $source,SqlStateSnapshot $sql,FileStateSnapshot $files,string $sqlName,string $fileName,StateAccountContainment $accounts,StateRecoveryCredentials $credentials,FactorRegistry $registry,TotpFactors $factors,HmacKeys $keys,string $site,string $scope,string $epoch,Clock $clock,callable $persist,array $manifest,?\SoSecurity\Auth\SessionRegistry $sessions=null,?FileStore $sessionStore=null):self
    {
        $self=new self($w,$source,$sql,$files,$sqlName,$fileName,$accounts,$credentials,$registry,$factors,$keys,$site,$scope,$epoch,$clock,$persist,$sessions,$sessionStore);$self->load($manifest);return $self;
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use exact covered credential installation dependencies and sealed effects.','configuration.credential_installation');}
    /** @return never */
    private static function changed():void{throw new StorageException('Credential installation differs from its sealed before/after image.','account.installation_changed');}
    private function now():int{$now=$this->d()[14]->now();if($now<1||$now>PHP_INT_MAX-31536001){self::invalid();}return $now;}
    private function d():array{return ($this->dependencies)();}
    private function m():array{return ($this->image)();}
    private function p():array{return ($this->packet)();}
    public function manifest():array{return $this->m();}
    public function binding():string{return $this->fingerprint;}
    public function count():int{return 1;}
    public function boundTo(LocalStateWitness $w):bool{return $this->d()[0]===$w&&$w->coversSnapshot($this->d()[1]);}
    public function usesAccounts(StateAccountContainment $accounts):bool{return $this->d()[6]===$accounts;}
    public function usesFactors(TotpFactors $factors):bool{return $this->d()[9]===$factors;}
    public function usesContext(string $context,HmacKeys $keys):bool{$d=$this->d();return $d[10]===$keys&&$d[9]->statePolicy($d[11],$d[12],$d[13],$keys)['context']===$context;}
    private function layout(string $subject):array{return $this->d()[6]->installationLayout($subject);}
    private function namespace(string $subject):string{$d=$this->d();return hash('sha256',json_encode(['SoSecurity.Account.Ledger.1','account-factor-directory:'.hash('sha256',json_encode([$d[11],$subject])),$d[12],$d[13]],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));}
    private function selectors(string $subject):array
    {
        $l=$this->layout($subject);$n=$this->namespace($subject);return ['account'=>['table'=>$l['table'],'key'=>[$l['columns']['scope']=>$l['scope'],$l['columns']['subject']=>$subject],'columns'=>array_values($l['columns'])],'root'=>['table'=>'sosecurity_account_roots','key'=>['namespace'=>$n],'columns'=>array_keys(Ledger::rootTypes())],'pointer'=>['table'=>'sosecurity_account_records','key'=>['namespace'=>$n,'record_id'=>hash('sha256','SoSecurity.Account.FactorRegistry.Pointer.1.'.$subject)],'columns'=>array_keys(Ledger::recordTypes())],'count'=>['table'=>'sosecurity_account_records','key'=>['namespace'=>$n],'columns'=>[],'count'=>true]];
    }
    private function sessionContext(string $subject):?array
    {
        $d=$this->d();if($d[16]===null){return null;}$v=$d[16]->credentialInstallationContext($d[17],$d[8],$d[0],$d[12],$subject);
        if($v===null||$v['clock']!==$d[14]||!$d[3]->coversReference($v['reference'])){self::invalid();}return $v;
    }
    private function sessionAfter(string $subject,string $nonce,int $now):string
    {
        $epoch=hash('sha256','SoSecurity.Account.InstalledSessionEpoch.1.'.$this->d()[0]->binding().$nonce.$subject);
        return Codec::encode(new Change(\SoSecurity\Auth\RegistryState::empty($epoch,$now),0,true));
    }
    private function capture(string $subject,string $file,?string $priorFile=null):array
    {
        $d=$this->d();$selectors=['new_factor'=>$file];if($priorFile!==null){$selectors['prior_factor']=$priorFile;}$session=$this->sessionContext($subject);if($session!==null){$selectors['sessions']=$session['reference']['file'];}$view=$d[1]->capture([$d[4]=>$this->selectors($subject),$d[5]=>$selectors]);$sql=$view->part($d[4]);$files=$view->part($d[5]);if(!$sql instanceof SqlStateCapture||!$files instanceof FileStateCapture||!$sql->matches($d[2])||!$files->matches($d[3])){self::invalid();}$rows=[$sql->row('account'),$sql->row('root'),$sql->row('pointer')];foreach($rows as $row){if(!is_array($row)){self::changed();}}if(($sql->row('count')['count']??null)!==1){self::changed();}return [$view->digest(),$rows,$files->file('new_factor'),$session===null?null:$files->file('sessions'),$priorFile===null?null:$files->file('prior_factor')];
    }
    /** Only the authenticated directory's exact prior coordinate is retired. No old secret is exported. */
    private function retirement(array $prior,string $subject,string $newFile,string $context):array
    {
        $d=$this->d();$key=Guard::key('mfa-totp',$prior['slot_scope'],$prior['slot_subject']);$ref=$d[9]->stateReference($prior['slot_scope'],$prior['slot_subject'],$context);$session=$this->sessionContext($subject);
        if($ref===null||!$d[3]->coversReference($ref)||$ref['file']===$newFile||($session!==null&&$ref['file']===$session['reference']['file'])){self::invalid();}
        $view=$this->capture($subject,$newFile,$ref['file']);$raw=$view[4];$migration=null;
        if($raw!==null){$outer=json_decode($raw,true,32);if(!is_array($outer)||array_keys($outer)!==['expires','value']||$outer['expires']!==0||!is_array($outer['value'])){self::changed();}$value=$outer['value'];
            if(($value['v']??null)===1){if(!in_array($prior['origin'],['legacy','none'],true)||$prior['slot_scope']!==$d[12]||$prior['slot_subject']!==$subject){self::changed();}$payload=\SoSecurity\Mfa\TotpFactorState::read($value,$this->now());}
            else{$frame=ManagedFactorFrame::read($context,$d[10],$key,$value);$migration=$frame['migration'];$payload=$frame['payload'];if($payload!==null){$payload=\SoSecurity\Mfa\TotpFactorState::read($payload,$this->now());}}
            if($payload!==null&&($payload['enabled']['id']??'')!==$prior['factor_id']){self::changed();}
        }
        $frame=['v'=>$migration===null?2:3,'context'=>$context,'key'=>$d[10]->currentId(),'payload'=>null];if($migration!==null){$frame['migration']=$migration;}$frame['seal']=bin2hex($d[10]->sign('SoSecurity.Mfa.ManagedFactor.1.'.$key.':'.ManagedFactorFrame::encode($frame)));
        return [$view[0],['key'=>$key,'reference'=>$ref,'before'=>$raw===null?null:hash('sha256',$raw),'after'=>Codec::encode(new Change($frame,0,true))]];
    }
    /** Coordinates are derived from the encrypted, authenticated prior directory; never supplied twice. */
    private function retirementEntry(array $manifest):?array
    {
        if(!isset($manifest['retirement'])){return null;}$d=$this->d();$prior=$manifest['prior'];$profile=$d[9]->statePolicy($d[11],$d[12],$d[13],$d[10]);$ref=$d[9]->stateReference($prior['scope'],$prior['subject'],$profile['context']);if($ref===null){self::invalid();}
        return ['key'=>Guard::key('mfa-totp',$prior['scope'],$prior['subject']),'reference'=>$ref,'before'=>$manifest['retirement']['before'],'after'=>$manifest['retirement']['after']];
    }
    private function directory(array $rows,string $subject):array
    {
        $d=$this->d();$policy=$d[8]->ledgerPolicy($d[10]);$n=$this->namespace($subject);$root=LedgerState::authenticate($rows[1],true,$n,$d[13],$policy->fingerprint(),1,$policy->maximumEntries(),$d[10],$this->now());$record=$rows[2];$payload=$record['payload'];unset($record['payload']);$record['body_length']=strlen($payload);$record=LedgerState::authenticate($record,false,$n,$d[13],$policy->fingerprint(),1,$policy->maximumEntries(),$d[10],$this->now());LedgerState::single($root,$record,1);$record['payload']=LedgerState::payload($record,$payload);return FactorDirectoryState::read($d[11],$d[12],$d[13],$record,$subject);
    }
    private function sign(array $row,bool $root):array{$keys=$this->d()[10];$row['seal_key']=$keys->currentId();$row['seal']=bin2hex($keys->sign(LedgerState::encoded($row,$root)));return $row;}
    private function prepareRecord(array $record):void
    {
        $d=$this->d();$entry=$record['entry'];$subject=$entry['selection']['subject'];$profile=$d[9]->statePolicy($d[11],$d[12],$d[13],$d[10]);$key=Guard::key('mfa-totp',$d[12],$entry['slot_subject']);$ref=$d[9]->stateReference($d[12],$entry['slot_subject'],$profile['context']);if($ref===null||!$d[3]->coversReference($ref)){self::invalid();}$view=$this->capture($subject,$ref['file']);if($view[0]!==$entry['selection']['observed']||$view[2]!==null){self::changed();}$before=$view[1];$prior=$this->directory($before,$subject);if(in_array($prior['origin'],['migrating'],true)){self::changed();}$nonce=bin2hex(random_bytes(32));$now=$this->now();if($now>=$entry['expires']){self::changed();}$after=$before;$layout=$this->layout($subject);$after[0][$layout['columns']['password']]=$entry['password'];$after[0][$layout['columns']['credential_version']]=hash('sha256','SoSecurity.Account.InstalledCredential.1.'.$d[0]->binding().$nonce.$subject);
        $pointer=['format'=>1,'purpose'=>'managed_factor','subject'=>$subject,'origin'=>'recovery','slot_scope'=>$d[12],'slot_subject'=>$entry['slot_subject'],'factor_id'=>$entry['id'],'generation'=>substr($nonce,0,32)];$payload=json_encode($pointer,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);$after[2]['revision']++;$after[2]['updated_at']=$now;$after[2]['retire_at']=$now+1209600;$after[2]['payload_bytes']=strlen($payload);$after[2]['payload_digest']=hash('sha256',$payload);$after[2]['payload']=$payload;$after[2]=$this->sign($after[2],false);$after[1]['revision']++;$after[1]['observed_at']=$now;$after[1]['history_digest']=hash('sha256','SoSecurity.Account.History.1.'.$after[1]['namespace'].$after[2]['record_id'].$after[2]['seal']);$after[1]=$this->sign($after[1],true);
        $frame=['v'=>2,'context'=>$profile['context'],'key'=>$d[10]->currentId(),'payload'=>$entry['factor']];$frame['seal']=bin2hex($d[10]->sign('SoSecurity.Mfa.ManagedFactor.1.'.$key.':'.ManagedFactorFrame::encode($frame)));$raw=Codec::encode(new Change($frame,0,true));$packet=['record'=>$record,'before'=>array_map([StateCredentialInstallManifest::class,'pack'],$before),'after'=>array_map([StateCredentialInstallManifest::class,'pack'],$after),'factor'=>$raw];
        $manifest=['format'=>2,'context'=>$d[0]->binding(),'generation'=>$d[0]->generation(),'source'=>$d[1]->fingerprint(),'sql'=>$d[2]->fingerprint(),'files'=>$d[3]->fingerprint(),'sql_name'=>$d[4],'file_name'=>$d[5],'account_plan'=>$d[6]->binding(),'subject'=>$subject,'candidate'=>$entry['id'],'material'=>hash('sha256','SoSecurity.Account.StateCredentialMaterial.1.'.json_encode([$entry['selection'],$entry['password'],$entry['factor'],$entry['confirmed'],$entry['expires']],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)),'nonce'=>$nonce,'observed'=>$view[0],'packet'=>$d[9]->sealCredentialInstallation($d[0]->binding().':'.$nonce,$packet),'before'=>array_map([StateCredentialInstallManifest::class,'hash'],$before),'after'=>array_map([StateCredentialInstallManifest::class,'hash'],$after),'factor'=>['key'=>$key,'file'=>$ref['file'],'after'=>hash('sha256',$raw)],'prior'=>['scope'=>$prior['slot_scope'],'subject'=>$prior['slot_subject'],'factor_id'=>$prior['factor_id']],'expires'=>$entry['expires']];$session=$this->sessionContext($subject);if($session!==null){$manifest['format']=3;$manifest['session']=['key'=>$session['key'],'reference'=>$session['reference'],'policy'=>$session['policy'],'before'=>$view[3]===null?null:hash('sha256',$view[3]),'after'=>$this->sessionAfter($subject,$nonce,$now)];}list($observed,$retirement)=$this->retirement($prior,$subject,$ref['file'],$profile['context']);if($observed!==$view[0]){self::changed();}$manifest['format']+=2;$manifest['retirement']=['before'=>$retirement['before'],'after'=>$retirement['after']];$this->load($manifest);
    }
    private function load(array $manifest):void
    {
        if(!StateCredentialInstallManifest::valid($manifest)){self::invalid();}$manifest=json_decode(json_encode($manifest,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES),true,8);$d=$this->d();foreach(['context'=>$d[0]->binding(),'generation'=>$d[0]->generation(),'source'=>$d[1]->fingerprint(),'sql'=>$d[2]->fingerprint(),'files'=>$d[3]->fingerprint(),'sql_name'=>$d[4],'file_name'=>$d[5],'account_plan'=>$d[6]->binding()] as $k=>$v){if($manifest[$k]!==$v){self::invalid();}}
        $packet=$d[9]->openCredentialInstallation($d[0]->binding().':'.$manifest['nonce'],$manifest['packet']);if(array_keys($packet)!==['record','before','after','factor']||!is_array($packet['before'])||!is_array($packet['after'])||array_keys($packet['before'])!==[0,1,2]||array_keys($packet['after'])!==[0,1,2]){self::invalid();}$before=array_map([StateCredentialInstallManifest::class,'unpack'],$packet['before']);$after=array_map([StateCredentialInstallManifest::class,'unpack'],$packet['after']);if(array_map([StateCredentialInstallManifest::class,'hash'],$before)!==$manifest['before']||array_map([StateCredentialInstallManifest::class,'hash'],$after)!==$manifest['after']||!is_string($packet['factor'])||strlen($packet['factor'])>65536||hash('sha256',$packet['factor'])!==$manifest['factor']['after']){self::invalid();}
        $entry=$packet['record']['entry']??null;$selector=$packet['record']['selector']??null;$layout=$this->layout($manifest['subject']);if(!is_array($entry)||!is_string($selector)||hash('sha256',$selector)!==($entry['proof']??null)||$entry['phase']!=='confirmed'||$entry['id']!==$manifest['candidate']||$entry['selection']['context']!==$manifest['context']||$entry['selection']['generation']!==$manifest['generation']||$entry['selection']['subject']!==$manifest['subject']||$entry['expires']!==$manifest['expires']||!HashBudget::allows($entry['password'])){self::invalid();}
        if($before[0][$layout['columns']['scope']]!==$layout['scope']||$before[0][$layout['columns']['subject']]!==$manifest['subject']||$entry['slot_subject']!=='state-recovery:'.$manifest['candidate']||$entry['selection']['observed']!==$manifest['observed']||hash('sha256','SoSecurity.Account.StateCredentialMaterial.1.'.json_encode([$entry['selection'],$entry['password'],$entry['factor'],$entry['confirmed'],$entry['expires']],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES))!==$manifest['material']){self::invalid();}$expected=$before[0];$expected[$layout['columns']['password']]=$entry['password'];$expected[$layout['columns']['credential_version']]=hash('sha256','SoSecurity.Account.InstalledCredential.1.'.$d[0]->binding().$manifest['nonce'].$manifest['subject']);if($expected!==$after[0]||$before[0][$layout['columns']['password']]!==null||$before[0][$layout['columns']['status']]!=='disabled'||$after[0][$layout['columns']['roles']]!=='[]'||$after[0][$layout['columns']['verified']]!==0||$after[0][$layout['columns']['mfa_required']]!==1){self::invalid();}$oldPointer=$this->directory($before,$manifest['subject']);if($manifest['prior']!==['scope'=>$oldPointer['slot_scope'],'subject'=>$oldPointer['slot_subject'],'factor_id'=>$oldPointer['factor_id']]||!$d[6]->matchesContainedRow($before[0],$manifest['subject'],$entry['selection']['operation'],$entry['selection']['row'])||$entry['selection']['plan']!==$manifest['account_plan']){self::invalid();}$pointer=$this->directory($after,$manifest['subject']);$at=$after[2]['updated_at'];if($at<$entry['confirmed']||$at>=$entry['expires']){self::invalid();}$pointerExpected=['format'=>1,'purpose'=>'managed_factor','subject'=>$manifest['subject'],'origin'=>'recovery','slot_scope'=>$d[12],'slot_subject'=>$entry['slot_subject'],'factor_id'=>$entry['id'],'generation'=>substr($manifest['nonce'],0,32)];$payloadExpected=json_encode($pointerExpected,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);$recordExpected=$before[2];$recordExpected['revision']++;$recordExpected['updated_at']=$at;$recordExpected['retire_at']=$at+1209600;$recordExpected['payload_bytes']=strlen($payloadExpected);$recordExpected['payload_digest']=hash('sha256',$payloadExpected);$recordExpected['payload']=$payloadExpected;$rootExpected=$before[1];$rootExpected['revision']++;$rootExpected['observed_at']=$at;$rootExpected['history_digest']=hash('sha256','SoSecurity.Account.History.1.'.$rootExpected['namespace'].$after[2]['record_id'].$after[2]['seal']);foreach([[$recordExpected,$after[2]],[$rootExpected,$after[1]]] as $pair){unset($pair[0]['seal_key'],$pair[0]['seal'],$pair[1]['seal_key'],$pair[1]['seal']);if($pair[0]!==$pair[1]){self::invalid();}}if($pointer['origin']!=='recovery'||$pointer['slot_scope']!==$d[12]||$pointer['slot_subject']!==$entry['slot_subject']||$pointer['factor_id']!==$entry['id']||$after[1]['revision']!==$before[1]['revision']+1||$after[2]['revision']!==$before[2]['revision']+1){self::invalid();}
        $profile=$d[9]->statePolicy($d[11],$d[12],$d[13],$d[10]);$ref=$d[9]->stateReference($d[12],$entry['slot_subject'],$profile['context']);if($ref===null||$ref['file']!==$manifest['factor']['file']||!$d[3]->coversReference($ref)||Guard::key('mfa-totp',$d[12],$entry['slot_subject'])!==$manifest['factor']['key']){self::invalid();}$frame=ManagedFactorFrame::read($profile['context'],$d[10],$manifest['factor']['key'],Codec::decode($packet['factor'],$this->now()));if($frame['payload']!==$entry['factor']||$frame['migration']!==null){self::invalid();}
        $session=$this->sessionContext($manifest['subject']);if(in_array($manifest['format'],[3,5],true)!==($session!==null)){self::invalid();}
        if($session!==null){$v=$manifest['session'];if($v['key']!==$session['key']||$v['reference']!==$session['reference']||$v['policy']!==$session['policy']||$v['after']!==$this->sessionAfter($manifest['subject'],$manifest['nonce'],$at)||$v['reference']['file']===$manifest['factor']['file']){self::invalid();}}
        if(isset($manifest['retirement'])){$r=$this->retirementEntry($manifest);if($r===null){self::invalid();}
            if(!$d[3]->coversReference($r['reference'])||$r['reference']['file']===$manifest['factor']['file']||($session!==null&&$r['reference']['file']===$manifest['session']['reference']['file'])){self::invalid();}
            $outer=json_decode($r['after'],true,32);if(!is_array($outer)||array_keys($outer)!==['expires','value']||$outer['expires']!==0){self::invalid();}$retired=ManagedFactorFrame::read($profile['context'],$d[10],$r['key'],$outer['value']);if($retired['payload']!==null||Codec::encode(new Change($outer['value'],0,true))!==$r['after']){self::invalid();}
        }
        $this->image=static function()use($manifest):array{return $manifest;};$this->packet=static function()use($packet):array{return $packet;};$this->fingerprint=hash('sha256','SoSecurity.Account.StateCredentialInstallation.1.'.StateCredentialInstallManifest::fingerprint($manifest));
    }
    private function rows():array{return [array_map([StateCredentialInstallManifest::class,'unpack'],$this->p()['before']),array_map([StateCredentialInstallManifest::class,'unpack'],$this->p()['after'])];}
    private function view():array
    {
        $m=$this->m();$r=$this->retirementEntry($m);$v=$this->capture($m['subject'],$m['factor']['file'],$r['reference']['file']??null);$hashes=array_map([StateCredentialInstallManifest::class,'hash'],$v[1]);if($hashes!==$m['before']&&$hashes!==$m['after']){self::changed();}if($v[2]!==null&&hash('sha256',$v[2])!==$m['factor']['after']){self::changed();}if(isset($m['session'])&&$v[3]!==$m['session']['after']&&($v[3]===null?null:hash('sha256',$v[3]))!==$m['session']['before']){self::changed();}if(isset($m['retirement'])&&$v[4]!==$m['retirement']['after']&&($v[4]===null?null:hash('sha256',$v[4]))!==$m['retirement']['before']){self::changed();}return $v;
    }
    public function observed():string{return $this->view()[0];}
    public function initialFor(array $state):bool{return $this->initial&&hash('sha256',json_encode($state,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES))===$this->p()['record']['entry']['selection']['authority']&&$this->now()<$this->m()['expires']&&$this->observed()===$this->m()['observed'];}
    public function candidateCurrent():bool{return $this->d()[7]->currentInstallation($this,$this->d()[0]);}
    public function guard(LocalStateWitness $w,string $operation):void{if(!$this->boundTo($w)||!$w->credentialInstallationActive($this,$operation)){self::invalid();}if($this->execution!==null){($this->execution)()[1]->check('account.witness_timeout');}$w->credentialInstallationCurrent($this,$operation);}
    public function replacement(LocalStateWitness $w,string $operation,FileStore $store,string $key,?string $raw):string
    {
        $this->guard($w,$operation);$m=$this->m();$d=$this->d();
        if(isset($m['session'])&&$key===$m['session']['key']){$v=$m['session'];if($store!==$d[17]||$store->snapshotReference($key)!==$v['reference']||($raw!==$v['after']&&($raw===null?null:hash('sha256',$raw))!==$v['before'])){self::changed();}return $v['after'];}
        if(($r=$this->retirementEntry($m))!==null&&$key===$r['key']){if($store->snapshotReference($key)!==$r['reference']||($raw!==$r['after']&&($raw===null?null:hash('sha256',$raw))!==$r['before'])){self::changed();}return $r['after'];}
        $ref=$d[9]->stateReference($d[12],$this->p()['record']['entry']['slot_subject'],$d[9]->statePolicy($d[11],$d[12],$d[13],$d[10])['context']);if($key!==$m['factor']['key']||$store->snapshotReference($key)!==$ref||($raw!==null&&hash('sha256',$raw)!==$m['factor']['after'])){self::changed();}return $this->p()['factor'];
    }
    public function persist(LocalStateWitness $w,string $operation,FileStore $store,string $key,$handle):void
    {
        $this->guard($w,$operation);$m=$this->m();$session=isset($m['session'])&&$key===$m['session']['key']&&$store===$this->d()[17];$retirement=$this->retirementEntry($m);if((!$session&&$key!==$m['factor']['key']&&$key!==($retirement['key']??null))||!is_resource($handle)||($this->d()[15])($handle)!==true){throw new StorageException('Credential file persistence is unknown.','account.installation_persistence');}$this->guard($w,$operation);
    }
    public function candidateFor(StateRecoveryCredentials $service,LocalStateWitness $w):array{if(!$this->boundTo($w)||$service!==$this->d()[7]){self::invalid();}return $this->p()['record'];}
    public function consumption(StateRecoveryCredentials $service,LocalStateWitness $w,string $operation):array{$this->guard($w,$operation);if($service!==$this->d()[7]){self::invalid();}return $this->p()['record'];}
    private function quote(string $v,string $driver):string{return ($driver==='mysql'?'`':'"').$v.($driver==='mysql'?'`':'"');}
    public function apply(LocalStateWitness $w,string $operation,Deadline $deadline):void
    {
        if(!$this->boundTo($w)||!$w->credentialInstallationActive($this,$operation)){self::invalid();}$this->execution=static function()use($operation,$deadline):array{return [$operation,$deadline];};$this->guard($w,$operation);$view=$this->view();if(!$w->credentialInstallationActive($this,$operation,$view[0])){self::changed();}$d=$this->d();$d[9]->installCredentialState($this->m()['factor']['key'],$this,$w,$operation);if(($retirement=$this->retirementEntry($this->m()))!==null){$d[9]->installCredentialState($retirement['key'],$this,$w,$operation);}if(isset($this->m()['session'])){$d[17]->installCredentialState($this->m()['session']['key'],$this,$w,$operation);}$this->guard($w,$operation);$view=$this->view();
        if(array_map([StateCredentialInstallManifest::class,'hash'],$view[1])===$this->m()['before']){$unit=SqlTransaction::forCredentialInstallation($d[2]->connection(),$d[14],30000,$this,$w,$operation);$driver=$unit->driver();$specs=array_values($this->selectors($this->m()['subject']));$rows=$this->rows();
            $unit->run(function()use($unit,$driver,$specs,$rows,$d,$w,$operation):void{
                foreach(array_slice($specs,0,3) as $spec){$where=[];$args=[];foreach($spec['key'] as $k=>$v){$where[]=$this->quote($k,$driver).'=:'.$k;$args[$k]=$v;}$q=$unit->query('SELECT 1 FROM '.$unit->prefix().$this->quote($spec['table'],$driver).' WHERE '.implode(' AND ',$where).($driver==='mysql'?' FOR UPDATE':''),$args);$q->fetchColumn();$q->closeCursor();}$d[6]->installationDependencies($unit,$this,$w,$operation);
                foreach(array_slice($specs,0,3) as $i=>$spec){$this->guard($w,$operation);$where=[];$set=[];$args=[];$blobs=[];foreach($rows[0][$i] as $column=>$value){$name='old_'.$column;$q=$this->quote($column,$driver);if($value===null){$where[]=$q.' IS NULL';}else{$where[]=(is_string($value)?($driver==='mysql'?'BINARY '.$q:'CAST('.$q.' AS BLOB)'):$q).'=:'.$name;$args[$name]=$value;if(is_string($value)){$blobs[]=$name;}}}foreach($rows[1][$i] as $column=>$value){$name='new_'.$column;$set[]=$this->quote($column,$driver).'=:'.$name;$args[$name]=$value;if($i===2&&$column==='payload'){$blobs[]=$name;}}$q=$unit->query('UPDATE '.$unit->prefix().$this->quote($spec['table'],$driver).' SET '.implode(',',$set).' WHERE '.implode(' AND ',$where),$args,$blobs);$count=$q->rowCount();$q->closeCursor();if($count!==1){self::changed();}}
            },null,function()use($w,$operation):void{$this->guard($w,$operation);},null,$deadline);
        }
        $this->installed($w,$operation);$d[7]->consumeInstallation($this,$w,$operation);$this->guard($w,$operation);
    }
    public function installed(LocalStateWitness $w,string $operation):string{$this->guard($w,$operation);$v=$this->view();if(array_map([StateCredentialInstallManifest::class,'hash'],$v[1])!==$this->m()['after']||$v[2]!==$this->p()['factor']||(isset($this->m()['session'])&&$v[3]!==$this->m()['session']['after'])||(isset($this->m()['retirement'])&&$v[4]!==$this->m()['retirement']['after'])){self::changed();}return $v[0];}
    public function __debugInfo():array{return ['state_credential_installation'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
