<?php
declare(strict_types=1);
// Synthetic registry proof for isolated file-pipeline tests; real credential protocols require separate HTTP evidence.
final class DownloadEnvironment
{
    public $base;
    public $source;
    public $temporary;
    public $web;
    public $path;
    public $contents;
    public $file;
    public $currentFile;
    public $clock;
    public $account;
    public $provider;
    public $sessions;
    public $credential;
    public $authorizer;
    public $downloads;
    public $guard=true;
    public $guards=0;
    public $reloads=0;
    public $onReload;
    public $offline=false;
    public function __construct(?SoSecurity\Download\Policy $policy=null,string $contents="Verified\0binary\xffbytes\n")
    {
        $this->base=privateDirectory();$this->source=$this->base.'/source';$this->temporary=$this->base.'/temporary';$this->web=$this->base.'/web';foreach([$this->source,$this->temporary,$this->web] as $directory){mkdir($directory,0700);}
        $this->path=$this->source.'/payload.bin';$this->contents=$contents;file_put_contents($this->path,$contents);chmod($this->path,0600);$this->file=$this->metadata();$this->currentFile=$this->file;$this->clock=new TestClock();$this->account=new SoSecurity\Auth\Account('tenant','alice','1',true,['editor']);
        $this->provider=new SoSecurity\Auth\CallbackIdentityProvider(static function(){return null;},function(string $scope,string $subject){if($this->offline){throw new RuntimeException('PRIVATE-DOWNLOAD-AUTHORITY');}return $scope==='tenant'&&$subject==='alice'?$this->account:null;});
        $this->sessions=new SoSecurity\Auth\SessionRegistry(new SoSecurity\Storage\MemoryStore($this->clock),$this->provider,null,$this->clock,1000,3600);
        $identity=(new SoSecurity\Auth\IdentityState($this->provider,null))->load('tenant','alice');$epoch=$this->sessions->epoch('tenant','alice');$this->credential=$this->sessions->register('tenant','alice',$identity['fingerprint'],$epoch);
        $this->authorizer=new SoSecurity\Authorization\Authorizer($this->provider,new SoSecurity\Authorization\RolePolicy(['file.download'=>['type'=>'file','roles'=>['editor'],'fields'=>[],'owner_attribute'=>'owner']]));
        $this->downloads=new SoSecurity\Download\Downloads($this->source,$this->temporary,$this->web,$policy,$this->clock);
    }
    public function metadata(?string $contents=null,string $relative='payload.bin',string $name='报告 "2026".bin',string $revision='1'):SoSecurity\Download\File
    {
        $contents=$contents ?? $this->contents;return new SoSecurity\Download\File(new SoSecurity\Authorization\Resource('tenant','file','a',$revision,['owner'=>'alice']),$relative,$name,strlen($contents),hash('sha256',$contents));
    }
    public function access():SoSecurity\Download\SessionAccess
    {
        return new SoSecurity\Download\SessionAccess($this->sessions,$this->authorizer,'tenant','alice',$this->credential->token(),function(){++$this->guards;return $this->guard;});
    }
    public function reload(string $scope,string $type,string $id):?SoSecurity\Download\File
    {
        ++$this->reloads;if($this->onReload!==null){($this->onReload)($this->reloads);}if($this->offline){throw new RuntimeException('PRIVATE-DOWNLOAD-INDEX');}return $this->currentFile;
    }
    public function prepare(?SoSecurity\Download\Request $request=null,?SoSecurity\Download\Access $access=null,?SoSecurity\Download\File $file=null):SoSecurity\Download\Transfer
    {
        return $this->downloads->prepare($file ?? $this->file,$request ?? new SoSecurity\Download\Request(),$access ?? $this->access(),[$this,'reload']);
    }
    public function cleanup():void
    {
        if(!is_dir($this->base)){return;}
        $iterator=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->base,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
        foreach($iterator as $file){if($file->isDir()&&!$file->isLink()){@chmod($file->getPathname(),0700);rmdir($file->getPathname());}else{if(!$file->isLink()){@chmod($file->getPathname(),0600);}unlink($file->getPathname());}}rmdir($this->base);
    }
    public function __destruct(){$this->cleanup();}
}
function downloadCase(callable $test,?SoSecurity\Download\Policy $policy=null,string $contents="Verified\0binary\xffbytes\n"):void
{
    $environment=new DownloadEnvironment($policy,$contents);try{$test($environment);}finally{$GLOBALS['download_read_hook']=null;$environment->cleanup();}
}
