<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Mfa\TotpFactors;
use SoSecurity\Mfa\TotpFactorState;
use SoSecurity\Password\PasswordHasher;
use SoSecurity\Password\HashBudget;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\Guard;

/** Persistent candidate preparation/possession proof. Never account installation, activation or recovery approval. */
final class StateRecoveryCredentials
{
    private $dependencies;
    private $binding;
    public function __construct(StateBoundary $drafts,FileStore $store,TotpFactors $factors,PasswordHasher $hasher,HmacKeys $keys,string $site,string $scope,string $epoch)
    {
        $profile=$factors->statePolicy($site,$scope,$epoch,$keys);if(!$drafts->semanticAuthority()||!$drafts->coversStore($store)||$profile===null){self::invalid();}Guard::label($site);Guard::label($scope);$protected=$drafts->protect($store);
        $this->binding=hash('sha256',json_encode(['SoSecurity.Account.StateRecoveryCredentials.1',$drafts->binding(),$store->snapshotReference(Guard::key('state-credential-drafts',$scope,'profile')),$profile['context'],$profile['reference'],$hasher->profile(),$hasher->parameters(),$site,$scope,$epoch],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));$clock=$profile['clock'];
        $this->dependencies=static function()use($drafts,$protected,$factors,$hasher,$keys,$site,$scope,$epoch,$clock):array{return [$drafts,$protected,$factors,$hasher,$keys,$site,$scope,$epoch,$clock];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use independent protected FileStore drafts and the exact managed target factor/key profile.','configuration.state_credentials');}
    /** @return never */
    private static function corrupt():void{throw new StorageException('Credential preparation state is corrupt or inconsistent.','account.credentials_corrupt');}
    private function d():array{return ($this->dependencies)();}
    private static function encode(array $v):string{$raw=json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);if(!is_string($raw)){self::corrupt();}return $raw;}
    private function now():int{$now=$this->d()[8]->now();if(!is_int($now)||$now<1||$now>PHP_INT_MAX-86400){self::corrupt();}return $now;}
    private function selection(LocalStateWitness $witness,StateAccountContainment $accounts,array $manifest,string $subject,callable $budget):array
    {
        $d=$this->d();if(!$witness->matches($d[5],$d[6],$d[7])||!$witness->usesKeys($d[4])||!$d[2]->coveredBy($witness)){self::invalid();}return $witness->credentialSelection($accounts,$manifest,$subject,$d[0],$budget);
    }
    private function state($v,int $now):array
    {
        if($v===null){return ['format'=>1,'binding'=>$this->binding,'updated'=>$now,'drafts'=>[]];}
        if(!is_array($v)||array_keys($v)!==['format','binding','updated','drafts','key','seal']||$v['format']!==1||$v['binding']!==$this->binding||!is_int($v['updated'])||$v['updated']<1||$v['updated']>$now||!is_array($v['drafts'])||count($v['drafts'])>4||!is_string($v['key'])||!is_string($v['seal'])||preg_match('/\A[a-f0-9]{64}\z/D',$v['seal'])!==1){self::corrupt();}$seal=$v['seal'];unset($v['seal']);if(!$this->d()[4]->verify($v['key'],'SoSecurity.Account.StateRecoveryCredentials.State.1.'.self::encode($v),hex2bin($seal))){self::corrupt();}unset($v['key']);
        foreach($v['drafts'] as $id=>$entry){
            if(!is_string($id)||preg_match('/\A[a-f0-9]{32}\z/D',$id)!==1||!is_array($entry)||array_keys($entry)!==['selection','slot_subject','id','proof','password','factor','phase','attempts','issued','expires','confirmed']||$entry['id']!==$id||!is_array($entry['selection'])||array_keys($entry['selection'])!==['authority','context','generation','plan','operation','scope','subject','row','observed']||!is_string($entry['slot_subject'])||$entry['slot_subject']!=='state-recovery:'.$id||!is_string($entry['proof'])||preg_match('/\A[a-f0-9]{64}\z/D',$entry['proof'])!==1||!is_string($entry['password'])||strlen($entry['password'])>4096||!HashBudget::allows($entry['password'])||!in_array($entry['phase'],['prepared','confirmed'],true)||!is_int($entry['attempts'])||$entry['attempts']<0||$entry['attempts']>5||!is_int($entry['issued'])||$entry['issued']<1||!is_int($entry['expires'])||$entry['expires']!==$entry['issued']+300||$entry['issued']>$now){self::corrupt();}
            foreach(['authority','context','generation','plan','operation','row','observed'] as $field){if(!is_string($entry['selection'][$field])||preg_match('/\A[a-f0-9]{64}\z/D',$entry['selection'][$field])!==1){self::corrupt();}}foreach(['scope','subject'] as $field){$label=$entry['selection'][$field];if(!is_string($label)||strlen($label)<1||strlen($label)>256||preg_match('//u',$label)!==1||preg_match('/[\x00-\x1f\x7f]/',$label)){self::corrupt();}}
            if($entry['expires']<=$now){unset($v['drafts'][$id]);continue;}$factor=TotpFactorState::read($entry['factor'],$now);if($factor===null||$factor['recovery']!==[]||$factor['failures']!==0||$factor['blocked_until']!==0){self::corrupt();}
            if($entry['phase']==='prepared'){if($entry['confirmed']!==null||$factor['enabled']!==null||$factor['pending']===null||$factor['pending']['id']!==$id||$factor['pending']['expires']!==$entry['expires']){self::corrupt();}}
            else{if(!is_int($entry['confirmed'])||$entry['confirmed']<$entry['issued']||$entry['confirmed']>=$entry['expires']||$factor['pending']!==null||$factor['enabled']===null||$factor['enabled']['id']!==$id||$factor['enabled']['last_step']<0){self::corrupt();}}
        }$v['updated']=$now;return $v;
    }
    private function change(array $v,$result):Change{$v['key']=$this->d()[4]->currentId();$v['seal']=bin2hex($this->d()[4]->sign('SoSecurity.Account.StateRecoveryCredentials.State.1.'.self::encode($v)));if(strlen(self::encode($v))>60000){self::corrupt();}return new Change($v,0,$result);}
    private function run(string $action,string $key,callable $work)
    {
        $d=$this->d();return $d[0]->run('state.credentials.'.$action,static function()use($d,$key,$work){return $d[1]->transact($key,$work);});
    }
    private function key(LocalStateWitness $witness):string{return Guard::key('state-credential-drafts',$this->d()[6],$witness->binding());}
    private static function reference(string $token):?array{if(strlen($token)!==101){return null;}if(preg_match('/\Asc1\.([a-f0-9]{32})\.([a-f0-9]{64})\z/D',$token,$m)!==1){return null;}return ['id'=>$m[1],'proof'=>hash('sha256',$token)];}
    /** Four live candidates per authority, five proof attempts, a fixed 300-second lifetime. */
    public function prepare(LocalStateWitness $witness,StateAccountContainment $accounts,array $manifest,string $subject,string $accountLabel,callable $budget):StateCredentialEnrollment
    {
        Guard::label($accountLabel);$selection=$this->selection($witness,$accounts,$manifest,$subject,$budget);$key=$this->key($witness);$now=$this->now();$space=$this->run('capacity',$key,function($raw)use($now):Change{$state=$this->state($raw,$now);return $this->change($state,count($state['drafts'])<4);});if(!$space){throw new SecurityException('Credential preparation capacity is exhausted.','account.credentials_capacity');}
        $d=$this->d();$id=bin2hex(random_bytes(16));$selector='sc1.'.$id.'.'.bin2hex(random_bytes(32));$password=bin2hex(random_bytes(32));$hash=$d[3]->hash($password);$slot='state-recovery:'.$id;$factor=$d[2]->recoveryCredentialDraft($d[6],$slot,$id,$accountLabel);$issued=$factor['state']['updated'];$checked=$this->now();if($checked<$issued||$checked>=$issued+300){throw new SecurityException('Credential preparation clock changed; prepare again.','account.credentials_clock');}
        $entry=['selection'=>$selection,'slot_subject'=>$slot,'id'=>$id,'proof'=>hash('sha256',$selector),'password'=>$hash,'factor'=>$factor['state'],'phase'=>'prepared','attempts'=>0,'issued'=>$issued,'expires'=>$issued+300,'confirmed'=>null];
        $saved=$this->run('prepare',$key,function($raw)use($entry,$id,$issued):Change{$state=$this->state($raw,$issued);if(count($state['drafts'])>=4||isset($state['drafts'][$id])){return $this->change($state,false);}$state['drafts'][$id]=$entry;ksort($state['drafts'],SORT_STRING);return $this->change($state,true);});if(!$saved){throw new SecurityException('Credential preparation capacity changed.','account.credentials_capacity');}return new StateCredentialEnrollment($selector,$password,$factor['enrollment']);
    }
    private function snapshot(string $key,array $reference,array $selection,int $now):?array
    {
        return $this->run('read',$key,function($raw)use($reference,$selection,$now):Change{$state=$this->state($raw,$now);$entry=$state['drafts'][$reference['id']]??null;if($entry===null||!hash_equals($entry['proof'],$reference['proof'])||$entry['selection']!==$selection){$entry=null;}return $this->change($state,$entry);});
    }
    public function confirm(LocalStateWitness $witness,StateAccountContainment $accounts,array $manifest,string $subject,string $selector,$password,$code,callable $budget):bool
    {
        $reference=self::reference($selector);if($reference===null||!is_string($password)||preg_match('/\A[a-f0-9]{64}\z/D',$password)!==1||!is_string($code)||preg_match('/\A[0-9]{6,8}\z/D',$code)!==1){return false;}$selection=$this->selection($witness,$accounts,$manifest,$subject,$budget);$now=$this->now();$key=$this->key($witness);$entry=$this->snapshot($key,$reference,$selection,$now);if($entry===null||$entry['phase']!=='prepared'||$entry['attempts']>=5){return false;}
        $d=$this->d();$factor=$d[3]->verify($password,$entry['password'])?$d[2]->confirmRecoveryCredential($d[6],$entry['slot_subject'],$entry['factor'],$code):null;$finished=$this->now();if($finished<$now){throw new SecurityException('Credential clock moved backwards.','account.credentials_clock');}
        return $this->run('confirm',$key,function($raw)use($entry,$reference,$factor,$finished):Change{$state=$this->state($raw,$finished);$old=$state['drafts'][$reference['id']]??null;if($old!==$entry){return $this->change($state,false);}++$state['drafts'][$reference['id']]['attempts'];if($factor===null){return $this->change($state,false);}$state['drafts'][$reference['id']]['factor']=$factor;$state['drafts'][$reference['id']]['phase']='confirmed';$state['drafts'][$reference['id']]['confirmed']=$finished;return $this->change($state,true);});
    }
    /** Non-secret live candidate description, not an installation grant or a current business identity. */
    public function describe(LocalStateWitness $witness,StateAccountContainment $accounts,array $manifest,string $subject,string $selector,callable $budget):?array
    {
        $ref=self::reference($selector);if($ref===null){return null;}$selection=$this->selection($witness,$accounts,$manifest,$subject,$budget);$entry=$this->snapshot($this->key($witness),$ref,$selection,$this->now());if($entry===null||$entry['phase']!=='confirmed'){return null;}$material=hash('sha256','SoSecurity.Account.StateCredentialMaterial.1.'.self::encode([$selection,$entry['password'],$entry['factor'],$entry['confirmed'],$entry['expires']]));return ['selection'=>$selection,'candidate'=>$entry['id'],'slot_subject'=>$entry['slot_subject'],'factor_id'=>$entry['factor']['enabled']['id'],'material'=>$material,'confirmed'=>$entry['confirmed'],'expires'=>$entry['expires']];
    }
    /** @internal Sensitive candidate bytes for the fixed native plan; never return from a host endpoint or log. */
    public function installationRecord(LocalStateWitness $witness,StateAccountContainment $accounts,array $manifest,string $subject,string $selector,callable $budget):array
    {
        $ref=self::reference($selector);if($ref===null){self::invalid();}$selection=$this->selection($witness,$accounts,$manifest,$subject,$budget);$entry=$this->snapshot($this->key($witness),$ref,$selection,$this->now());if($entry===null||$entry['phase']!=='confirmed'){throw new SecurityException('A live confirmed credential candidate is required.','account.credentials_unconfirmed');}return ['entry'=>$entry,'selector'=>$selector];
    }
    public function matchesInstallation(TotpFactors $factors,HmacKeys $keys,string $site,string $scope,string $epoch):bool{$d=$this->d();return $d[2]===$factors&&$d[4]===$keys&&$d[5]===$site&&$d[6]===$scope&&$d[7]===$epoch;}
    public function currentInstallation(StateCredentialInstallation $plan,LocalStateWitness $witness):bool
    {
        $v=$plan->candidateFor($this,$witness);$ref=self::reference($v['selector']);return $ref!==null&&$this->snapshot($this->key($witness),$ref,$v['entry']['selection'],$this->now())===$v['entry'];
    }
    public function consumeInstallation(StateCredentialInstallation $plan,LocalStateWitness $witness,string $operation):void
    {
        $v=$plan->consumption($this,$witness,$operation);$reference=self::reference($v['selector']);if($reference===null){self::invalid();}$now=$this->now();$key=$this->key($witness);
        $ok=$this->run('consume',$key,function($raw)use($v,$reference,$now):Change{$state=$this->state($raw,$now);$old=$state['drafts'][$reference['id']]??null;if($old!==null&&$old!==$v['entry']){return $this->change($state,false);}unset($state['drafts'][$reference['id']]);return $this->change($state,true);});if(!$ok){throw new StorageException('The exact credential candidate changed before consumption.','account.credentials_changed');}
    }
    public function __debugInfo():array{return ['state_recovery_credentials'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
