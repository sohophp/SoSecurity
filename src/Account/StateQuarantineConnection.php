<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Upload\Policy;
use SoSecurity\Upload\QuarantineFiles;
use SoSecurity\Upload\Scanner;

/** Exact metadata/content graph and repeatable current host authorization. No recovery or lease takeover. */
final class StateQuarantineConnection
{
    private $dependencies;
    private $busy=false;
    /** Guard(action, authority scope, queue scope, target id, descriptor): actual actor or null/false.
     * Called before reading input and repeatedly for the exact selected resource. Must have no business side effects. */
    public function __construct(StateBoundary $boundary,LocalStateWitness $witness,CompositeStateSnapshot $source,FileStateSnapshot $metadata,string $metadataName,FileStore $store,QuarantineStateSnapshot $content,string $contentName,string $site,string $scope,string $epoch,Clock $clock,Scanner $scanner,callable $guard,int $milliseconds=10000)
    {
        new Deadline($milliseconds);
        if(!$boundary->semanticAuthority()||!$boundary->boundTo($witness)||!$witness->matches($site,$scope,$epoch)||!$witness->coversSnapshot($source)||!$source->contains($metadataName,$metadata)||!$source->contains($contentName,$content)||!$metadata->coversStore($store)||!$store->usesClock($clock)){self::invalid();}
        $binding=hash('sha256','SoSecurity.StateQuarantineConnection.1.'.json_encode([$boundary->binding(),$source->fingerprint(),$metadata->fingerprint(),$content->fingerprint(),$metadataName,$contentName,$site,$scope,$epoch,$milliseconds]));
        $content->protect($boundary,$witness,$source,$contentName);$boundary->bindFileStore($store);
        $this->dependencies=static function()use($boundary,$source,$metadata,$metadataName,$store,$content,$site,$scope,$clock,$scanner,$guard,$milliseconds,$binding):array{return compact('boundary','source','metadata','metadataName','store','content','site','scope','clock','scanner','guard','milliseconds','binding');};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Declare the exact quarantine graph, scanner and current host authority.','configuration.state_quarantine');}
    public function validate(AtomicStore $store,QuarantineFiles $files,Policy $policy,array $options,Clock $clock,Scanner $scanner,string $documentRoot):void
    {
        $d=($this->dependencies)();$web=realpath($documentRoot);if($web===false){self::invalid();}
        foreach($d['metadata']->storageDomains() as $domain){$path=$domain['path'];if(DIRECTORY_SEPARATOR==='\\'){$path=strtolower($path);$web=strtolower($web);}if($path===$web||strpos($path,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0){self::invalid();}}
        if($store!==$d['store']||$clock!==$d['clock']||$scanner!==$d['scanner']||!$d['content']->matches($files,$policy,$options['maximum_entries'],$options['maximum_total_bytes'])){self::invalid();}
    }
    public function validateFactory(string $site,Clock $clock,?StateBoundary $boundary):void
    {
        $d=($this->dependencies)();if($site!==$d['site']||$clock!==$d['clock']||($boundary!==null&&$boundary!==$d['boundary'])||$d['store']->snapshotFile('quarantine-state-context')!==hash('sha256',$site.':shared'."\0".'quarantine-state-context').'.json'){self::invalid();}
    }
    public function store():FileStore{return ($this->dependencies)()['store'];}
    private function authority(string $action,string $queue,?string $target,array $descriptor):?string
    {
        $d=($this->dependencies)();$scope=$d['scope'];
        try{$actor=($d['guard'])($action,$scope,$queue,$target,$descriptor);if($actor===false||$actor===null){return null;}if(!is_string($actor)){throw new \RuntimeException('Invalid actor');}Guard::label($actor);if(preg_match('//u',$actor)!==1){throw new \RuntimeException('Invalid actor encoding');}return $actor;}
        catch(\Throwable $error){throw new DependencyException('Quarantine authority unavailable.','upload.quarantine_authority');}
    }
    private function tick(Deadline $deadline,int &$seen):int
    {
        $deadline->check('upload.quarantine_timeout');try{$now=($this->dependencies)()['clock']->now();}catch(\Throwable $error){throw new StorageException('Quarantine clock unavailable.','upload.quarantine_clock');}
        if($now<=0||$now>PHP_INT_MAX-2592001||$now<$seen){throw new StorageException('Quarantine clock invalid.','upload.quarantine_clock');}$seen=$now;return $now;
    }
    private function current(string $entry,string $queue,array $plan,string $actor,Deadline $deadline,int &$seen):int
    {
        if($this->authority($entry,$queue,$plan['target'],$plan['descriptor'])!==$actor){throw new SecurityException('Quarantine authority changed.','upload.quarantine_denied');}
        $now=$this->tick($deadline,$seen);if($plan['until']!==0&&$plan['until']<=$now){throw new SecurityException('Quarantine admission expired.','upload.quarantine_expired');}return $now;
    }
    private function approved(?array $plan):array{if($plan===null){self::invalid();}return $plan;}
    private function caller(?string $caller):string{if($caller===null){self::invalid();}return $caller;}
    /** Native queue callbacks prepare validated input, decide against captured bytes, then execute original operations. */
    public function run(string $action,string $queue,string $key,string $configuration,?string $target,callable $input,callable $prepare,callable $effect,callable $finish)
    {
        if(!in_array($action,['enqueue','inspect','items','process','rescan','reject','read','remove'],true)){self::invalid();}Guard::label($queue);$d=($this->dependencies)();
        if($this->busy||$d['boundary']->active()){throw new ConfigurationException('Enter native quarantine once before other effects.','configuration.state_quarantine_nested');}
        $this->busy=true;$deadline=new Deadline($d['milliseconds']);$seen=0;$entry='quarantine.'.$action;$plan=null;$caller=null;$result=null;
        try{
            $this->tick($deadline,$seen);$initial=$this->authority($entry,$queue,$target,[]);if($initial===null){throw new SecurityException('Quarantine admission denied.','upload.quarantine_denied');}
            $prepared=$input();$this->tick($deadline,$seen);
            $d['boundary']->run($entry,function()use($entry,$queue,$deadline,&$seen,&$plan,&$caller,&$result,$effect):void{
                $plan=$this->approved($plan);$caller=$this->caller($caller);$this->current($entry,$queue,$plan,$caller,$deadline,$seen);
                $result=$effect($plan['old'],$plan);$this->current($entry,$queue,$plan,$caller,$deadline,$seen);
            },function(string $expected)use($d,$entry,$queue,$key,$configuration,$initial,$prepared,$prepare,$deadline,&$seen,&$plan,&$caller,&$result){
                $now=$this->tick($deadline,$seen);$view=$d['source']->capture([$d['metadataName']=>['entry'=>$d['store']->snapshotFile($key)]]);$part=$view->part($d['metadataName']);
                if(!$view->matches($d['source'])||!hash_equals($expected,$view->digest())||!$part instanceof FileStateCapture||!$part->matches($d['metadata'])){throw new StorageException('Quarantine source changed.','account.witness_stale');}
                $raw=$part->file('entry');$old=$raw===null?null:Codec::decode($raw,$now);if($raw!==null){$envelope=json_decode($raw,true,32);if($envelope['expires']!==0){throw new StorageException('Quarantine ledgers must not expire.','storage.corrupt');}}
                $now=$this->tick($deadline,$seen);$plan=$prepare($old,$now,$prepared);$plan['old']=$old;$caller=$initial;
                $now=$this->current($entry,$queue,$plan,$caller,$deadline,$seen);$result=$plan['result'];if(!$plan['effect']){return false;}
                if(!$d['metadata']->canStoreFile($d['store']->snapshotFile($key))||($plan['bytes']!==0&&!$d['content']->canAdd($plan['bytes']))){throw new SecurityException('Quarantine physical capacity reached.','upload.quarantine_capacity');}
                $now=$this->current($entry,$queue,$plan,$caller,$deadline,$seen);
                $request=hash('sha256','SoSecurity.QuarantineAdmission.1.'.json_encode([$entry,$queue,$plan['target'],$plan['descriptor'],$expected,$plan['until']]));
                return StateOperation::quarantine($entry,$d['scope'],$caller,hash('sha256',$key.':'.($plan['target']??'')),$request,hash('sha256',$d['binding'].'.'.$configuration),$now);
            },null,$deadline);
            $plan=$this->approved($plan);$caller=$this->caller($caller);$now=$this->current($entry,$queue,$plan,$caller,$deadline,$seen);return $finish($result,$now);
        }finally{$this->busy=false;}
    }
    public function __debugInfo():array{return ['state_quarantine'=>'[redacted]'];}
    public function __clone(){self::invalid();}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
