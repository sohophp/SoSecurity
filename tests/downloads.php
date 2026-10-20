<?php
declare(strict_types=1);
namespace SoSecurity\Download {
    // Deterministic fault/race injection around actual bounded file reads; no production hook or substitute filesystem.
    function stream_get_contents($handle,$length=-1,$offset=-1){$value=\stream_get_contents($handle,$length,$offset);$hook=$GLOBALS['download_read_hook'] ?? null;if($hook!==null){$hook($handle,$value);}return $value;}
}
namespace {
require __DIR__.'/bootstrap.php';require __DIR__.'/download-support.php';
use SoSecurity\Authorization\Resource;
use SoSecurity\Download\File;
use SoSecurity\Download\Policy;
use SoSecurity\Download\Request;
use SoSecurity\Download\RangeException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

foreach([['unknown'=>1],['maximum_bytes'=>0],['maximum_bytes'=>268435457],['maximum_bytes'=>'1024'],['maximum_response_bytes'=>20971521],['io_milliseconds'=>0],['send_milliseconds'=>30001],['chunk_bytes'=>1023],['chunk_bytes'=>262145],['ranges'=>1]] as $options){Check::throws(ConfigurationException::class,static function()use($options){new Policy($options);});}
Check::same(4096,(new Policy(['maximum_bytes'=>4096]))->maximumResponseBytes());
$referenced=['maximum_bytes'=>4096,'maximum_response_bytes'=>null,'io_milliseconds'=>1000,'send_milliseconds'=>5000,'chunk_bytes'=>1024,'ranges'=>true];$aliases=[];
foreach($referenced as $name=>&$value){$aliases[$name]=&$value;}unset($value);$unchanged=json_decode(json_encode($referenced),true);$stable=new Policy($aliases);$options=$stable->options();Check::same($unchanged,$referenced);
foreach($referenced as $name=>&$value){$value=$name==='ranges'?false:-1;}unset($value);Check::same($options,$stable->options());Check::same(4096,$stable->maximumResponseBytes());
$returned=$stable->options();$returned['maximum_bytes']=999999;Check::same($options,$stable->options());
$aliasedLimit=1;$bounded=new Policy(['maximum_bytes'=>&$aliasedLimit]);$aliasedLimit=268435456;
downloadCase(static function(DownloadEnvironment $e){Check::throws(ValidationException::class,static function()use($e){$e->prepare();});},$bounded,'too large');
$resource=new Resource('tenant','file','a','1',['owner'=>'alice']);
foreach(['','/etc/passwd','../outside','a/../b','a//b','./a','a/.','file://x','a\\b','%2e%2e/a','a?b','a#b',str_repeat('x',256),implode('/',array_fill(0,17,'a'))] as $path){Check::throws(ConfigurationException::class,static function()use($resource,$path){new File($resource,$path,'safe.bin',1,hash('sha256','x'));});}
foreach(['','.hidden','name.','name ',"a\rb","a\nb",'a/b','a\\b','a:b',"a\xe2\x80\xaeb",str_repeat('x',256)] as $name){Check::throws(ConfigurationException::class,static function()use($resource,$name){new File($resource,'safe.bin',$name,1,hash('sha256','x'));});}
foreach([-1,536870913] as $bytes){Check::throws(ConfigurationException::class,static function()use($resource,$bytes){new File($resource,'safe.bin','safe.bin',$bytes,hash('sha256','x'));});}
Check::throws(ConfigurationException::class,static function()use($resource){new File($resource,'safe.bin','safe.bin',1,'bad');});
foreach(['PUT','DELETE','get',''] as $method){Check::throws(ValidationException::class,static function()use($method){new Request($method);});}
foreach([['Range'=>'bytes=0-1,3-4'],['Range'=>'items=0-1'],['Range'=>'bytes=-'],['Range'=>'bytes=999999999999999999999-'],['Range'=>"bytes=0-1\r\nX: y"],['range'=>'bytes=0-1','Range'=>'bytes=2-3']] as $headers){Check::throws(Throwable::class,static function()use($headers){new Request('GET',$headers);});}
foreach([['Range'=>[]],['x'=>str_repeat('x',2049)],['bad.name'=>'value']] as $headers){Check::throws(ValidationException::class,static function()use($headers){new Request('GET',$headers);});}
downloadCase(static function(DownloadEnvironment $e){
    $transfer=$e->prepare();$headers=$transfer->headers();Check::same(200,$transfer->status());Check::same((string)strlen($e->contents),$headers['Content-Length']);Check::same('application/octet-stream',$headers['Content-Type']);Check::same('nosniff',$headers['X-Content-Type-Options']);Check::same('no-store, private',$headers['Cache-Control']);Check::same('no-referrer',$headers['Referrer-Policy']);
    Check::same(true,strpos($headers['Content-Disposition'],"filename*=UTF-8''".rawurlencode($e->file->filename()))!==false);Check::same(false,strpos(json_encode($headers),$e->base)!==false);Check::same([],glob($e->temporary.'/.download-*'));
    $body='';$written=$transfer->send(static function(string $chunk)use(&$body):int{$body.=$chunk;return strlen($chunk);});Check::same($e->contents,$body);Check::same(strlen($body),$written);Check::same(true,$transfer->complete());Check::same(strlen($body),$transfer->bytesRead());Check::same('',$transfer->read());Check::same(1,$e->guards);
    Check::same(true,$e->reloads>=3);Check::same('{}',json_encode($transfer));Check::same(false,strpos(print_r($transfer,true),$e->base)!==false);Check::throws(ConfigurationException::class,static function()use($transfer){serialize($transfer);});
});
downloadCase(static function(DownloadEnvironment $e){
    $head=$e->prepare(new Request('HEAD',['Range'=>'bytes=0-0']));Check::same(200,$head->status());Check::same((string)strlen($e->contents),$head->headers()['Content-Length']);$calls=0;Check::same(0,$head->send(static function()use(&$calls){++$calls;return 0;}));Check::same(0,$calls);Check::same(true,$head->complete());
});
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();Check::same('0',$response->headers()['Content-Length']);Check::same('',$response->read());Check::same(true,$response->complete());},null,'');
$ranges=['bytes=0-0'=>[206,0,1],'bytes=2-5'=>[206,2,4],'bytes=2-'=>[206,2,8],'bytes=-3'=>[206,7,3],'bytes=-99999999999999999999'=>[206,0,10],'bytes=0-99999999999999999999'=>[206,0,10],'BYTES=0002-0005'=>[206,2,4]];
foreach($ranges as $range=>$expected){downloadCase(static function(DownloadEnvironment $e)use($range,$expected){$response=$e->prepare(new Request('GET',['Range'=>$range]));Check::same($expected[0],$response->status());Check::same((string)$expected[2],$response->headers()['Content-Length']);Check::same('bytes '.$expected[1].'-'.($expected[1]+$expected[2]-1).'/10',$response->headers()['Content-Range']);Check::same(substr($e->contents,$expected[1],$expected[2]),$response->read());},null,'0123456789');}
foreach(['bytes=10-','bytes=7-3','bytes=-0','bytes=99999999999999999999-'] as $range){downloadCase(static function(DownloadEnvironment $e)use($range){try{$e->prepare(new Request('GET',['Range'=>$range]));throw new LogicException('Expected range refusal.');}catch(RangeException $error){Check::same(10,$error->totalBytes());}Check::same([],glob($e->temporary.'/.download-*'));},null,'0123456789');}
downloadCase(static function(DownloadEnvironment $e){Check::throws(RangeException::class,static function()use($e){$e->prepare(new Request('GET',['Range'=>'bytes=0-0']));});},null,'');
foreach(['W/"old"','"old"','Wed, 01 Jan 2020 00:00:00 GMT'] as $condition){downloadCase(static function(DownloadEnvironment $e)use($condition){$response=$e->prepare(new Request('GET',['Range'=>'bytes=0-0','If-Range'=>$condition]));Check::same(200,$response->status());Check::same($e->contents,$response->read());});}
downloadCase(static function(DownloadEnvironment $e){$tag='"sha256-'.$e->file->sha256().'"';$response=$e->prepare(new Request('GET',['Range'=>'bytes=0-0','If-Range'=>$tag,'If-None-Match'=>'*']));Check::same(206,$response->status());Check::same(substr($e->contents,0,1),$response->read());});
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare(new Request('GET',['If-None-Match'=>'*','If-Modified-Since'=>'Wed, 01 Jan 2030 00:00:00 GMT']));Check::same(200,$response->status());Check::same($e->contents,$response->read());});
downloadCase(static function(DownloadEnvironment $e){Check::throws(RangeException::class,static function()use($e){$e->prepare(new Request('GET',['Range'=>'bytes=0-0']));});},new Policy(['ranges'=>false]));
downloadCase(static function(DownloadEnvironment $e){Check::throws(ValidationException::class,static function()use($e){$e->prepare();});Check::same('V',$e->prepare(new Request('GET',['Range'=>'bytes=0-0']))->read());},new Policy(['maximum_response_bytes'=>1]));
downloadCase(static function(DownloadEnvironment $e){Check::throws(ValidationException::class,static function()use($e){$e->prepare();});Check::same([],glob($e->temporary.'/.download-*'));},new Policy(['maximum_bytes'=>1]));
foreach([false,1,null,'yes'] as $guard){downloadCase(static function(DownloadEnvironment $e)use($guard){$e->guard=$guard;unlink($e->path);try{$e->prepare();throw new LogicException('Expected authentication denial.');}catch(SecurityException $error){Check::same('download.denied',$error->reason());}Check::same(0,$e->reloads);});}
downloadCase(static function(DownloadEnvironment $e){$wrong=new File(new Resource('other','file','a','1',['owner'=>'alice']),'missing.bin','safe.bin',1,hash('sha256','x'));Check::throws(SecurityException::class,static function()use($e,$wrong){$e->prepare(null,null,$wrong);});Check::same(0,$e->reloads);});
downloadCase(static function(DownloadEnvironment $e){$e->account=new SoSecurity\Auth\Account('tenant','alice','2',true,['reader']);unlink($e->path);Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same(0,$e->reloads);});
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();$e->sessions->revokeAll('tenant','alice');Check::throws(SecurityException::class,static function()use($response){$response->read();});Check::same(0,$response->bytesRead());Check::same(false,$response->complete());Check::throws(StorageException::class,static function()use($response){$response->read();});});
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();$e->currentFile=$e->metadata(null,'payload.bin','Renamed.bin');Check::throws(SecurityException::class,static function()use($response){$response->headers();});Check::throws(StorageException::class,static function()use($response){$response->read();});});
downloadCase(static function(DownloadEnvironment $e){$e->currentFile=null;Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same([],glob($e->temporary.'/.download-*'));});
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();$e->offline=true;try{$response->read();throw new LogicException('Expected source outage.');}catch(DependencyException $error){Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}Check::same(0,$response->bytesRead());});
downloadCase(static function(DownloadEnvironment $e){$e->onReload=static function(int $count)use($e){if($count===2){$e->account=new SoSecurity\Auth\Account('tenant','alice','2',false,['editor']);}};Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same([],glob($e->temporary.'/.download-*'));});
downloadCase(static function(DownloadEnvironment $e){$mtime=filemtime($e->path);file_put_contents($e->path,str_repeat('X',strlen($e->contents)));touch($e->path,$mtime);Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same([],glob($e->temporary.'/.download-*'));});
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();file_put_contents($e->path,str_repeat('X',strlen($e->contents)));Check::same($e->contents,$response->read());});
downloadCase(static function(DownloadEnvironment $e){
    $mtime=filemtime($e->path);$GLOBALS['download_read_hook']=static function($handle)use($e,$mtime){if(stream_get_meta_data($handle)['uri']===$e->path){$GLOBALS['download_read_hook']=null;file_put_contents($e->path,str_repeat('B',strlen($e->contents)));touch($e->path,$mtime);}};
    Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same([],glob($e->temporary.'/.download-*'));
},new Policy(['chunk_bytes'=>1024]),str_repeat('A',65536));
foreach(['symbolic','hard','directory','public','missing'] as $kind){downloadCase(static function(DownloadEnvironment $e)use($kind){
    if($kind==='public'){chmod($e->path,0644);}elseif($kind==='hard'){link($e->path,$e->source.'/alias.bin');}else{unlink($e->path);if($kind==='symbolic'){symlink(__FILE__,$e->path);}elseif($kind==='directory'){mkdir($e->path,0700);}}
    Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same([],glob($e->temporary.'/.download-*'));
});}
downloadCase(static function(DownloadEnvironment $e){mkdir($e->source.'/nested',0700);rename($e->path,$e->source.'/nested/payload.bin');$e->file=$e->metadata(null,'nested/payload.bin');$e->currentFile=$e->file;Check::same($e->contents,$e->prepare()->read());chmod($e->source.'/nested',0755);Check::throws(StorageException::class,static function()use($e){$e->prepare();});});
downloadCase(static function(DownloadEnvironment $e){mkdir($e->base.'/outside',0700);rename($e->path,$e->base.'/outside/payload.bin');symlink($e->base.'/outside',$e->source.'/nested');$e->file=$e->metadata(null,'nested/payload.bin');$e->currentFile=$e->file;Check::throws(StorageException::class,static function()use($e){$e->prepare();});});
downloadCase(static function(DownloadEnvironment $e){$held=fopen($e->path,'rb');flock($held,LOCK_EX);$start=microtime(true);try{Check::throws(StorageException::class,static function()use($e){$e->prepare();});Check::same(true,microtime(true)-$start<2.0);}finally{flock($held,LOCK_UN);fclose($held);}},new Policy(['io_milliseconds'=>20]));
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();usleep(30000);Check::throws(StorageException::class,static function()use($response){$response->headers();});},new Policy(['send_milliseconds'=>10]));
foreach([-1,PHP_INT_MAX,99999,101000] as $now){downloadCase(static function(DownloadEnvironment $e)use($now){$response=$e->prepare();$e->clock->time=$now;Check::throws(SecurityException::class,static function()use($response){$response->read();});Check::same(0,$response->bytesRead());});}
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();$GLOBALS['download_read_hook']=static function($handle)use($e){if(strpos(stream_get_meta_data($handle)['uri'],$e->temporary.'/')===0){$e->clock->time=101000;}};Check::throws(SecurityException::class,static function()use($response){$response->read();});Check::same(0,$response->bytesRead());});
foreach(['role','metadata','revocation','outage'] as $change){downloadCase(static function(DownloadEnvironment $e)use($change){
    $response=$e->prepare();$GLOBALS['download_read_hook']=static function($handle)use($e,$change){if(strpos(stream_get_meta_data($handle)['uri'],$e->temporary.'/')!==0){return;}$GLOBALS['download_read_hook']=null;
        if($change==='role'){$e->account=new SoSecurity\Auth\Account('tenant','alice','2',true,['reader']);}
        elseif($change==='metadata'){$e->currentFile=$e->metadata(null,'payload.bin','changed.bin');}
        elseif($change==='revocation'){$e->sessions->revokeAll('tenant','alice');}
        else{$e->offline=true;}
    };
    Check::throws(SecurityException::class,static function()use($response){$response->read();});Check::same(0,$response->bytesRead());Check::same(false,$response->complete());Check::throws(StorageException::class,static function()use($response){$response->read();});
});}
foreach(['source','temporary'] as $which){downloadCase(static function(DownloadEnvironment $e)use($which){
    $directory=$which==='source'?$e->source:$e->temporary;rename($directory,$directory.'-old');mkdir($directory,0700);
    if($which==='source'){copy($directory.'-old/payload.bin',$e->path);chmod($e->path,0600);}
    Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same([],glob($e->temporary.'/.download-*'));
});}
downloadCase(static function(DownloadEnvironment $e){if(function_exists('posix_mkfifo')){unlink($e->path);Check::same(true,posix_mkfifo($e->path,0600));$started=microtime(true);Check::throws(SecurityException::class,static function()use($e){$e->prepare();});Check::same(true,microtime(true)-$started<1.0);}});
downloadCase(static function(DownloadEnvironment $e){$e->currentFile=new File(new Resource('another','file','a','1',['owner'=>'alice']),'payload.bin','safe.bin',strlen($e->contents),hash('sha256',$e->contents));Check::throws(ConfigurationException::class,static function()use($e){$e->prepare();});});
foreach([0,false,null,'1'] as $count){downloadCase(static function(DownloadEnvironment $e)use($count){$response=$e->prepare();Check::throws(StorageException::class,static function()use($response,$count){$response->send(static function()use($count){return $count;});});Check::same(false,$response->complete());});}
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();Check::throws(StorageException::class,static function()use($response){$response->send(static function(string $chunk):int{return strlen($chunk)-1;});});Check::same(false,$response->complete());Check::throws(StorageException::class,static function()use($response){$response->read();});});
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();try{$response->send(static function(){throw new RuntimeException('PRIVATE-OUTPUT');});throw new LogicException('Expected output rejection.');}catch(StorageException $error){Check::same('download.output',$error->reason());Check::same(null,$error->getPrevious());}Check::same(false,$response->complete());});
foreach([-1,PHP_INT_MAX,99999,104000] as $now){downloadCase(static function(DownloadEnvironment $e)use($now){$response=$e->prepare();$calls=0;Check::throws(SecurityException::class,static function()use($response,$e,$now,&$calls){$response->send(static function(string $chunk)use($e,$now,&$calls):int{++$calls;$e->clock->time=$now;return strlen($chunk);});});Check::same(1,$calls);Check::same(false,$response->complete());Check::throws(StorageException::class,static function()use($response){$response->read();});});}
downloadCase(static function(DownloadEnvironment $e){$response=$e->prepare();$calls=0;Check::throws(StorageException::class,static function()use($response,&$calls){$response->send(static function(string $chunk)use(&$calls):int{++$calls;usleep(1100000);return strlen($chunk);});});Check::same(1,$calls);Check::same(false,$response->complete());},new Policy(['send_milliseconds'=>1000]));
downloadCase(static function(DownloadEnvironment $e){
    $keys=new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('d',32)]);$links=new SoSecurity\Link\Links(new SoSecurity\Storage\MemoryStore($e->clock),$keys,'test',new SoSecurity\Link\Policy('https://files.example'),static function(){return true;},$e->clock);
    $factory=static function(File $file):SoSecurity\Link\Target{return new SoSecurity\Link\Target('file.download',$file->resource(),'/download',['id'=>$file->sourceResource()->id()]);};
    $issued=$links->issue($factory($e->file),true);$access=new SoSecurity\Download\LinkAccess($links,$factory,$issued->url());
    Check::throws(SecurityException::class,static function()use($e,$access){$e->prepare(new Request('GET',['Range'=>'bytes=0-0']),$access);});
    Check::throws(SecurityException::class,static function()use($e,$access){$e->prepare(new Request('HEAD'),$access);});Check::same($e->contents,$e->prepare(null,$access)->read());Check::throws(SecurityException::class,static function()use($e,$access){$e->prepare(null,$access);});
    $issued=$links->issue($factory($e->file));$access=new SoSecurity\Download\LinkAccess($links,$factory,$issued->url());$response=$e->prepare(new Request('GET',['Range'=>'bytes=0-0']),$access);Check::same(206,$response->status());$links->revoke($factory($e->file),$issued->id());Check::throws(SecurityException::class,static function()use($response){$response->read();});
    $badFactory=static function(File $file):SoSecurity\Link\Target{return new SoSecurity\Link\Target('file.download',$file->sourceResource(),'/download',['id'=>'a']);};
    Check::throws(ConfigurationException::class,static function()use($e,$links,$badFactory,$issued){$e->prepare(null,new SoSecurity\Download\LinkAccess($links,$badFactory,$issued->url()));});
});
downloadCase(static function(DownloadEnvironment $e){
    foreach([['directory'=>$e->source,'temporary_directory'=>$e->temporary,'document_root'=>$e->web,'policy'=>['unknown'=>true]],[],null] as $bad){Check::throws(ConfigurationException::class,static function()use($bad){SoSecurity\Security::fromArray(['site'=>'test','downloads'=>$bad]);});}
    Check::throws(ConfigurationException::class,static function(){SoSecurity\Security::fromArray(['site'=>'test'])->downloads();});
    $options=['directory'=>$e->source,'temporary_directory'=>$e->temporary,'document_root'=>$e->web];$security=SoSecurity\Security::fromArray(['site'=>'test','downloads'=>$options]);Check::same(20971520,$security->downloads()->policy()->maximumBytes());$diagnostic=json_encode($security->diagnose($e->web));Check::same(true,strpos($diagnostic,'downloads.content_version')!==false);Check::same(false,strpos($diagnostic,$e->base)!==false);
    Check::throws(ConfigurationException::class,static function()use($e){new SoSecurity\Download\Downloads($e->web,$e->temporary,$e->web);});
    Check::throws(ConfigurationException::class,static function()use($e){new SoSecurity\Download\Downloads($e->source.'/..',$e->temporary,$e->web);});
    foreach([$e->file,new Request(),$e->access(),$e->downloads] as $object){Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object){serialize($object);});Check::same(false,strpos(print_r($object,true),$e->base)!==false);}
    Check::throws(ConfigurationException::class,static function()use($e){$e->file->relativePath='../other';});
});
Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
echo 'PASS private downloads: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; content-bound metadata, real private-file snapshots, Session/signed access, raw ranges/headers, authority/clock/output failures and cleanup\n";
}
