<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\HmacKeys;

/** Bounded append-only recovery transitions, anchored by the independent witness, never a new approval authority. */
final class StateRecoveryAudit
{
    private $dependencies;
    private $busy=false;
    public function __construct(string $directory,HmacKeys $keys,callable $persist)
    {
        $stat=@lstat($directory);if(realpath($directory)!==$directory||!is_array($stat)||($stat['mode']&0170777)!==0040700){throw new ConfigurationException('Use a canonical private recovery audit directory and exact stable persistence.','configuration.recovery_audit');}
        $this->dependencies=static function()use($directory,$stat,$keys,$persist):array{return [$directory,$stat,$keys,$persist];};
    }
    private function d():array{return ($this->dependencies)();}
    /** @return never */
    private static function corrupt():void{throw new StorageException('Independent recovery audit is missing, changed or unconfirmed.','account.recovery_audit_corrupt');}
    private static function encode(array $value):string{$raw=json_encode($value,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);if(!is_string($raw)){self::corrupt();}return $raw;}
    private static function digest($v):bool{return is_string($v)&&preg_match('/\A[a-f0-9]{64}\z/D',$v)===1;}
    public function usesKeys(HmacKeys $keys):bool{return $this->d()[2]===$keys;}
    private function directory():void
    {
        $d=$this->d();clearstatcache(true,$d[0]);$s=@lstat($d[0]);if(realpath($d[0])!==$d[0]||!is_array($s)||($s['mode']&0170777)!==0040700||$s['dev']!==$d[1]['dev']||$s['ino']!==$d[1]['ino']||$s['uid']!==$d[1]['uid']){self::corrupt();}
    }
    public function storageDomain():array{$this->directory();$d=$this->d();return StateStorageDomain::directory($d[0],$d[1]);}
    public function binding(string $context):string{if(!self::digest($context)){self::corrupt();}$d=$this->d();return hash('sha256','SoSecurity.Account.StateRecoveryAudit.Binding.1.'.$context.':'.$d[0].':'.$d[1]['dev'].':'.$d[1]['ino']);}
    public function unused():bool{$this->directory();foreach(new \DirectoryIterator($this->d()[0]) as $file){if(!$file->isDot()){return false;}}return true;}
    private function stat(array $s,int $limit):void{if(($s['mode']&0170777)!==0100600||$s['uid']!==$this->d()[1]['uid']||$s['nlink']!==1||$s['size']<1||$s['size']>$limit){self::corrupt();}}
    private function read(string $name,int $limit,Deadline $deadline):string
    {
        $deadline->check('account.witness_timeout');$this->directory();$path=$this->d()[0].'/'.$name;clearstatcache(true,$path);$before=@lstat($path);if(!is_array($before)){self::corrupt();}$this->stat($before,$limit);$h=@fopen($path,'r+b');if($h===false){self::corrupt();}
        try{$opened=fstat($h);if(!is_array($opened)){self::corrupt();}$this->stat($opened,$limit);$raw=stream_get_contents($h,$limit+1);clearstatcache(true,$path);$named=@lstat($path);if(!is_array($named)){self::corrupt();}$this->stat($named,$limit);foreach([$before,$named] as $s){if($s['dev']!==$opened['dev']||$s['ino']!==$opened['ino']){self::corrupt();}}if(!is_string($raw)||strlen($raw)>$limit||strlen($raw)!==$opened['size']){self::corrupt();}$this->directory();$deadline->check('account.witness_timeout');return $raw;}finally{fclose($h);}
    }
    private function verifySeal(array $v,string $domain,bool $digest=false):void
    {
        if(!is_string($v['key']??null)||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])||!self::digest($v['seal']??null)){self::corrupt();}$seal=$v['seal'];unset($v['seal']);if(!$this->d()[2]->verify($v['key'],$domain.($digest?hash('sha256',self::encode($v)):self::encode($v)),hex2bin($seal))){self::corrupt();}
    }
    private function seal(array $v,string $domain,bool $digest=false):array{$v['key']=$this->d()[2]->currentId();$v['seal']=bin2hex($this->d()[2]->sign($domain.($digest?hash('sha256',self::encode($v)):self::encode($v))));return $v;}
    private function marker(string $context,Deadline $deadline):void
    {
        $raw=$this->read('context.json',1024,$deadline);$v=json_decode($raw,true,4);if(!is_array($v)||array_keys($v)!==['format','context','key','seal']||$v['format']!==1||$v['context']!==$context||self::encode($v)!==$raw){self::corrupt();}$this->verifySeal($v,'SoSecurity.Account.StateRecoveryAudit.Context.1.');
    }
    private function count(Deadline $deadline):int
    {
        $this->directory();$count=0;foreach(new \DirectoryIterator($this->d()[0]) as $file){$deadline->check('account.witness_timeout');if($file->isDot()){continue;}if(++$count>257||($file->getFilename()!=='context.json'&&preg_match('/\A[a-f0-9]{64}\.json\z/D',$file->getFilename())!==1)){self::corrupt();}$s=@lstat($file->getPathname());if(!is_array($s)){self::corrupt();}$this->stat($s,$file->getFilename()==='context.json'?1024:65536);}return $count;
    }
    private function handle($handle,string $path,int $limit):void
    {
        $this->directory();$opened=is_resource($handle)?fstat($handle):false;clearstatcache(true,$path);$named=@lstat($path);if(!is_array($opened)||!is_array($named)){self::corrupt();}$this->stat($opened,$limit);$this->stat($named,$limit);if($opened['dev']!==$named['dev']||$opened['ino']!==$named['ino']){self::corrupt();}
    }
    private function create(string $name,string $raw,Deadline $deadline,callable $guard):void
    {
        $guard();$deadline->check('account.witness_timeout');$this->directory();$path=$this->d()[0].'/'.$name;$h=@fopen($path,'x+b');if($h===false){self::corrupt();}
        try{if(!chmod($path,0600)||fwrite($h,$raw)!==strlen($raw)||!fflush($h)){self::corrupt();}$s=fstat($h);clearstatcache(true,$path);$named=@lstat($path);if(!is_array($s)||!is_array($named)){self::corrupt();}$this->stat($s,65536);if($named['dev']!==$s['dev']||$named['ino']!==$s['ino']){self::corrupt();}
            if(($this->d()[3])($h)!==true){self::corrupt();}$this->handle($h,$path,65536);$guard();if($this->read($name,65536,$deadline)!==$raw){self::corrupt();}
        }finally{fclose($h);}
    }
    public static function validAnchor($v):bool
    {
        return is_array($v)&&array_keys($v)===['journal','sequence','head','complete']&&self::digest($v['journal'])&&is_int($v['sequence'])&&$v['sequence']>=1&&$v['sequence']<=256&&self::digest($v['head'])&&is_bool($v['complete']);
    }
    private function record(string $context,string $head,int $sequence,Deadline $deadline):array
    {
        $raw=$this->read($head.'.json',65536,$deadline);if(!hash_equals($head,hash('sha256',$raw))){self::corrupt();}$v=json_decode($raw,true,5);
        if(!is_array($v)||array_keys($v)!==['format','context','sequence','previous','complete','before','after','key','seal']||!in_array($v['format'],[1,2],true)||$v['context']!==$context||$v['sequence']!==$sequence||($sequence===1?$v['previous']!==null:!self::digest($v['previous']))||!is_bool($v['complete'])||!is_string($v['before'])||strlen($v['before'])>16384||!is_string($v['after'])||strlen($v['after'])>16384||self::encode($v)!==$raw){self::corrupt();}$this->verifySeal($v,'SoSecurity.Account.StateRecoveryAudit.Record.'.$v['format'].'.',$v['format']===2);return $v;
    }
    private function root(string $raw,string $context,bool $sealed):array
    {
        $v=json_decode($raw,true,12);if(!is_array($v)||!in_array($v['format']??null,[2,3],true)||($v['context']??null)!==$context||self::encode($v)!==$raw){self::corrupt();}if($sealed){$this->verifySeal($v,'SoSecurity.Account.LocalStateWitness.Seal.'.$v['format'].'.');}elseif(isset($v['key'])||isset($v['seal'])||isset($v['recovery_audit'])){self::corrupt();}return $v;
    }
    /** Verify every referenced transition; no cache can hide a replaced historical record. */
    public function verify(string $context,array $anchor,Deadline $deadline):void
    {
        if(!self::validAnchor($anchor)||$anchor['journal']!==$this->binding($context)){self::corrupt();}$this->marker($context,$deadline);$this->count($deadline);$head=$anchor['head'];$complete=$anchor['complete'];$expected=null;
        for($sequence=$anchor['sequence'];$sequence>=1;--$sequence){
            $v=$this->record($context,$head,$sequence,$deadline);if($v['complete']!==$complete){self::corrupt();}$after=$this->root($v['after'],$context,false);if(!in_array($after['status']??null,['closed','quarantined','current'],true)){self::corrupt();}if($expected!==null&&$v['after']!==$expected){self::corrupt();}
            $before=$this->root($v['before'],$context,true);$parent=$before['recovery_audit']??null;
            if($sequence===1){if($parent!==null||$complete!==in_array($before['status']??null,['current','pending'],true)){self::corrupt();}}
            else{if(!self::validAnchor($parent)||$parent['journal']!==$anchor['journal']||$parent['sequence']!==$sequence-1||$parent['head']!==$v['previous']||$parent['complete']!==$complete){self::corrupt();}}
            unset($before['key'],$before['seal'],$before['recovery_audit']);$expected=in_array($before['status']??null,['closed','quarantined'],true)?self::encode($before):null;$head=$v['previous'];
        }
    }
    /** Only the exact owning witness can create the exact proposal while holding its recovery write scope. */
    public function append(LocalStateWitness $witness,string $before,string $after,?array $parent,Deadline $deadline):array
    {
        if($this->busy||!$witness->recoveryAuditActive($this,$before,$after)){throw new ConfigurationException('Use the owning witness recovery write scope.','configuration.recovery_audit');}$this->busy=true;
        try{$context=$witness->binding();$beforeState=$this->root($before,$context,true);$this->root($after,$context,false);if(($beforeState['recovery_audit']??null)!==$parent){self::corrupt();}
            // Capture the concrete audit; a static callback must never borrow a caller's object or execution context.
            $audit=$this;$guard=static function()use($witness,$audit,$before,$after):void{if(!$witness->recoveryAuditActive($audit,$before,$after)){self::corrupt();}};
            if($parent===null){if($this->unused()){$marker=$this->seal(['format'=>1,'context'=>$context],'SoSecurity.Account.StateRecoveryAudit.Context.1.');$this->create('context.json',self::encode($marker),$deadline,$guard);}else{$this->marker($context,$deadline);}}
            else{$this->verify($context,$parent,$deadline);}
            $count=$this->count($deadline);$sequence=$parent===null?1:$parent['sequence']+1;if($count>=257||$sequence>256){throw new StorageException('Recovery audit reached its fixed 256-record capacity; retain isolation.','account.recovery_audit_capacity');}
            $complete=$parent===null?in_array($beforeState['status']??null,['current','pending'],true):$parent['complete'];$v=$this->seal(['format'=>2,'context'=>$context,'sequence'=>$sequence,'previous'=>$parent['head']??null,'complete'=>$complete,'before'=>$before,'after'=>$after],'SoSecurity.Account.StateRecoveryAudit.Record.2.',true);$raw=self::encode($v);if(strlen($raw)>65536){throw new StorageException('Recovery audit record exceeds its fixed encoding bound.','account.recovery_audit_capacity');}$head=hash('sha256',$raw);$path=$this->d()[0].'/'.$head.'.json';clearstatcache(true,$path);
            if(@lstat($path)!==false){if($this->read($head.'.json',65536,$deadline)!==$raw){self::corrupt();}/* An identical orphan is still explicitly re-flushed before it can be referenced. */$h=@fopen($path,'r+b');if($h===false){self::corrupt();}try{$this->handle($h,$path,65536);$guard();if(($this->d()[3])($h)!==true){self::corrupt();}$this->handle($h,$path,65536);$guard();if($this->read($head.'.json',65536,$deadline)!==$raw){self::corrupt();}}finally{fclose($h);}}
            else{$this->create($head.'.json',$raw,$deadline,$guard);}
            return ['journal'=>$this->binding($context),'sequence'=>$sequence,'head'=>$head,'complete'=>$complete];
        }finally{$this->busy=false;}
    }
    /** One bounded descending page; cursor authorization and exact root matching belong to LocalStateWitness. */
    public function page(string $context,array $anchor,int $offset,Deadline $deadline):array
    {
        $this->verify($context,$anchor,$deadline);if($offset<0||$offset>=$anchor['sequence']){self::corrupt();}$head=$anchor['head'];$sequence=$anchor['sequence'];for($i=0;$i<$offset;++$i){$head=$this->record($context,$head,$sequence--,$deadline)['previous'];}$events=[];
        for($i=0;$i<4&&$sequence>=1;++$i,--$sequence){$v=$this->record($context,$head,$sequence,$deadline);$events[]=['head'=>$head,'sequence'=>$sequence,'before'=>$this->root($v['before'],$context,true),'after'=>$this->root($v['after'],$context,false)];$head=$v['previous'];}return ['events'=>$events,'more'=>$sequence>=1,'offset'=>$offset+count($events)];
    }
    public function matchesHead(string $context,array $anchor,array $state,Deadline $deadline):bool{$v=$this->record($context,$anchor['head'],$anchor['sequence'],$deadline);unset($state['key'],$state['seal'],$state['recovery_audit']);return $v['after']===self::encode($state);}
    public function __debugInfo():array{return ['state_recovery_audit'=>'[redacted]'];}
    public function __clone(){throw new ConfigurationException('Reload recovery audit dependencies.','configuration.recovery_audit');}
    public function __sleep():array{throw new ConfigurationException('Do not serialize recovery audit dependencies.','configuration.recovery_audit');}
    public function __wakeup():void{throw new ConfigurationException('Reload recovery audit dependencies.','configuration.recovery_audit');}
    public function __set(string $name,$value):void{throw new ConfigurationException('Recovery audit is immutable.','configuration.immutable');}
}
