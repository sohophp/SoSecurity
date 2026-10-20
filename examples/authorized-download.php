<?php
declare(strict_types=1);
namespace SoSecurity\Examples\DownloadHttp;
ini_set('display_errors','0');
$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;
use PDO;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\PasswordIdentityProvider;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\Resource;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Concurrency\LeaseManager;
use SoSecurity\Concurrency\LeasePolicy;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Download\Access;
use SoSecurity\Download\Downloads;
use SoSecurity\Download\File;
use SoSecurity\Download\Grant;
use SoSecurity\Download\LinkAccess;
use SoSecurity\Download\RangeException;
use SoSecurity\Download\Request;
use SoSecurity\Download\SessionAccess;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Link\Links;
use SoSecurity\Link\Policy as LinkPolicy;
use SoSecurity\Link\Target;
use SoSecurity\Output\Escaper;
use SoSecurity\RateLimit\BudgetGroup;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;
const SCOPE='download-example';

/** Host composition: admit only after actual authorization; charge complete-source KiB even for one-byte ranges. */
final class ResourceAccess implements Access
{
    private $base;
    private $budgets;
    private $leases;
    private $owner;
    private $lease;
    private $used=false;
    public function __construct(Access $base,BudgetGroup $budgets,LeaseManager $leases){$this->base=$base;$this->budgets=$budgets;$this->leases=$leases;$this->owner=bin2hex(random_bytes(16));}
    public function authorize(File $file,Request $request):?Grant
    {
        if($this->used){return null;}$this->used=true;$grant=$this->base->authorize($file,$request);if($grant===null){return null;}
        $cost=max(1,intdiv($file->bytes()+1023,1024));$budget=$this->budgets->consume(SCOPE,'transfers',['requests'=>1,'kib'=>$cost]);
        if(!$budget->allowed()){throw new SecurityException('Download attempt budget exhausted.','download.rate');}
        $this->lease=$this->leases->acquire(SCOPE,'transfers',$this->owner);if($this->lease===null){throw new SecurityException('Download concurrency exhausted.','download.concurrent');}
        return new Grant($file->fingerprint(),min($grant->expiresAt(),$this->lease->expiresAt()),function(File $current)use($grant):bool{
            return $grant->check($current,time())&&$this->leases->verify(SCOPE,'transfers',$this->owner,$this->lease->token())!==null;
        },$grant->oneTime());
    }
    public function close():void {if($this->lease!==null){$lease=$this->lease;$this->lease=null;$this->leases->release(SCOPE,'transfers',$this->owner,$lease->token());}}
}
function output(int $status,array $data):void
{
    http_response_code($status);header('Cache-Control: no-store, private');header('Referrer-Policy: no-referrer');header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    if(session_status()===PHP_SESSION_ACTIVE){header('Set-Cookie: '.SessionSecurity::cookieHeader(getenv('SOSECURITY_DOWNLOAD_EXAMPLE_HTTPS')!=='0'),false);}
    if(strpos($_SERVER['HTTP_ACCEPT'] ?? '','application/json')!==false){header('Content-Type: application/json; charset=utf-8');echo json_encode($data);return;}
    header('Content-Type: text/html; charset=utf-8');echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>授权下载示例</title><style>body{font:16px/1.6 system-ui;max-width:44rem;margin:2rem auto;padding:0 1rem}form{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}label{display:grid;max-width:100%}input,button,select{font:inherit;max-width:100%;box-sizing:border-box}pre,a{white-space:pre-wrap;overflow-wrap:anywhere}</style><main><h1>授权下载示例</h1>';
    if(isset($data['issued_url'])){echo '<p>持有分享链接的人可下载授权版本，请妥善保管。一次GET可能被预取或安全扫描消耗；需要明确操作时请选择POST兑换。</p><a data-issued-link href="'.Escaper::html($data['issued_url']).'">下载分享文件</a>';}
    if(isset($data['csrf'])){
        $form='<form method="post"><input type="hidden" name="_csrf" value="'.Escaper::html($data['csrf']).'">';
        if(!empty($data['redemption'])){echo '<p>尚未消费下载授权。提交后开始一次下载，失败不恢复授权。</p>'.$form.'<button>明确兑换并下载</button></form>';}
        elseif(($data['stage'] ?? '')==='authenticated'){
            echo '<form method="get"><input type="hidden" name="delivery" value="private"><label>文件编号<input name="file_id" value="a" maxlength="64"></label><button data-private-download>下载我的文件</button></form>';
            echo $form.'<label>文件编号<input name="file_id" value="a" maxlength="64"></label><label>分享方式<select name="delivery"><option value="read">限期重复下载</option><option value="once">一次GET下载</option><option value="redeem">明确POST兑换</option></select></label><button name="action" value="issue">签发下载链接</button></form>';
            echo $form.'<label>文件编号<input name="file_id" value="a" maxlength="64"></label><label>链接编号<input name="link_id" maxlength="32"></label><button name="action" value="revoke">撤销链接</button></form>'.$form.'<button name="action" value="logout">退出</button></form>';
        }else{echo $form.'<label>账号<input name="username" maxlength="256" autocomplete="username"></label><label>密码<input type="password" name="password" maxlength="4096" autocomplete="current-password"></label><button name="action" value="login">登录</button></form>';}
    }
    $display=$data;unset($display['csrf'],$display['issued_url']);echo '<pre data-download-state>'.Escaper::html(json_encode($display,JSON_PRETTY_PRINT)).'</pre></main></html>';
}
function privateFile(string $name,int $maximum=0):string
{
    $path=getenv($name);$real=$path?realpath($path):false;$web=realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if($real===false||!is_file($real)||is_link($path)||(fileperms($real)&0077)!==0||$web===false||$real===$web||strpos($real,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0||($maximum>0&&filesize($real)>$maximum)){throw new \RuntimeException('Configure a private file outside the web root.');}return $real;
}
function passwordRecord(PDO $pdo,string $scope,string $value,bool $byUsername=false):?PasswordRecord
{
    if($scope!==SCOPE){return null;}$query=$pdo->prepare('SELECT subject,password_hash,version,enabled,roles FROM download_accounts WHERE tenant=:tenant AND '.($byUsername?'username':'subject').'=:value');$query->execute(['tenant'=>SCOPE,'value'=>$value]);$row=$query->fetch(PDO::FETCH_ASSOC);if(!is_array($row)){return null;}
    if(!is_string($row['roles'])||strlen($row['roles'])>4096||!in_array((string)$row['enabled'],['0','1'],true)){throw new \RuntimeException('Invalid account source.');}$roles=json_decode($row['roles'],true,4);
    if(!is_array($roles)||array_values($roles)!==$roles){throw new \RuntimeException('Invalid role source.');}return new PasswordRecord(new Account(SCOPE,$row['subject'],$row['version'],(int)$row['enabled']===1,$roles),$row['password_hash']);
}
/** Metadata only, loaded by tenant/object ID. Owner state is bound into every private or signed content version. */
function currentFile(PDO $pdo,string $scope,string $type,string $id):?File
{
    if($scope!==SCOPE||$type!=='file'||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$id)){return null;}
    $query=$pdo->prepare('SELECT owner,version,relative_path,filename,bytes,sha256,state FROM download_files WHERE tenant=:tenant AND id=:id');$query->execute(['tenant'=>SCOPE,'id'=>$id]);$row=$query->fetch(PDO::FETCH_ASSOC);
    if(!is_array($row)||$row['state']!=='ready'){return null;}$owner=passwordRecord($pdo,SCOPE,$row['owner']);if($owner===null||!$owner->account()->enabled()){return null;}
    $size=(string)$row['bytes'];if(!preg_match('/\A(?:0|[1-9][0-9]{0,8})\z/D',$size)){throw new \RuntimeException('Invalid bounded source size.');}
    return new File(new Resource(SCOPE,'file',$id,(string)$row['version'],['owner'=>$owner->account()->subject(),'owner_identity'=>$owner->identity()->fingerprint()]),$row['relative_path'],$row['filename'],(int)$size,$row['sha256']);
}
function startSession(bool $secure):array
{
    SessionSecurity::configure($secure);session_name('SoSecurityDownloadExample');ini_set('session.cookie_path',rtrim(str_replace('\\','/',dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/.').'/');
    if(!session_start()){throw new \RuntimeException('Cannot start protected host session.');}if(!isset($_SESSION['download_binding'])){$_SESSION['download_binding']=bin2hex(random_bytes(32));}
    return [new CsrfTokens(new SessionStore('download-controls')),$_SESSION['download_binding']];
}
$streaming=false;$transfer=null;$resourceAccess=null;
try {
    $database=new PDO('sqlite:'.privateFile('SOSECURITY_DOWNLOAD_EXAMPLE_DATABASE'),null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
    $json=file_get_contents(privateFile('SOSECURITY_DOWNLOAD_EXAMPLE_KEYS',16384),false,null,0,16385);if(!is_string($json)||strlen($json)>16384){throw new \RuntimeException('Invalid signing size.');}$data=json_decode($json,true);
    if(!is_array($data)||count($data)!==2||!is_string($data['current'] ?? null)||!is_array($data['keys'] ?? null)){throw new \RuntimeException('Invalid signing configuration.');}$secrets=[];
    foreach($data['keys'] as $id=>$encoded){if(!is_string($encoded)||!is_string($decoded=base64_decode($encoded,true))||base64_encode($decoded)!==$encoded){throw new \RuntimeException('Invalid signing key.');}$secrets[$id]=$decoded;}$keys=new \SoSecurity\Support\HmacKeys($data['current'],$secrets);
    $origin=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_ORIGIN');$storage=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_STORAGE');$dummy=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_DUMMY_HASH');$secure=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_HTTPS')!=='0';$path=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_PATH') ?: '/authorized-download.php';
    if(!$origin||!$storage||!$dummy){throw new \RuntimeException('Configure explicit origin, storage and credential source.');}$linkPolicy=new LinkPolicy($origin,300,86400,32,!$secure);
    if(($secure&&((strtolower($_SERVER['HTTPS'] ?? '')!=='on'&&($_SERVER['HTTPS'] ?? '')!=='1')||substr($origin,0,8)!=='https://'))||(!$secure&&substr($origin,0,7)!=='http://')||($_SERVER['HTTP_HOST'] ?? '')!==substr($origin,strpos($origin,'//')+2)){throw new \RuntimeException('Transport/Host does not match configured origin.');}
    $raw=$_SERVER['REQUEST_URI'] ?? '';if(strlen($raw)>2048||parse_url($raw,PHP_URL_PATH)!==$path){throw new ValidationException('Invalid raw route.','download.input');}$method=$_SERVER['REQUEST_METHOD'] ?? 'GET';
    if(!in_array($method,['GET','HEAD','POST'],true)){header('Allow: GET, HEAD, POST');output(405,['error'=>'download.method']);return;}
    $storageRoot=realpath($storage);$web=realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if($storageRoot===false||$storageRoot!==rtrim($storage,'/')||$web===false||$storageRoot===$web||strpos($storageRoot,rtrim($web,'/').'/')===0){throw new \RuntimeException('Configure canonical private state outside the actual web root.');}
    $store=new FileStore($storageRoot,'download-example');$ip=(new \SoSecurity\Http\ClientIp())->resolve($_SERVER);$entry=(new \SoSecurity\RateLimit\RateLimiter($store,new \SoSecurity\RateLimit\Policy(240,60,[10],120)))->consume('entry',$ip);
    if(!$entry->allowed){header('Retry-After: '.$entry->retryAfter);output(429,['error'=>'download.rate']);return;}
    $provider=new PasswordIdentityProvider(function(string $scope,string $username)use($database){return passwordRecord($database,$scope,$username,true);},function(string $scope,string $subject)use($database){return passwordRecord($database,$scope,$subject);},new \SoSecurity\Password\PasswordHasher(),$dummy);
    $sessions=new SessionRegistry($store,$provider);$authorizer=new Authorizer($provider,new RolePolicy(['file.download'=>['type'=>'file','roles'=>['editor','reader'],'fields'=>[],'owner_attribute'=>'owner'],'file.share'=>['type'=>'file','roles'=>['editor'],'fields'=>[],'owner_attribute'=>'owner']]));
    $verified=null;$protected=false;$readAllowed=false;$csrf=null;$binding='';
    $links=new Links($store,$keys,SCOPE,$linkPolicy,function(string $operation,Target $target,string $actualMethod)use(&$verified,&$protected,&$readAllowed,$authorizer,$method):bool{
        if($operation==='verify'){return $readAllowed&&$actualMethod===$method;}
        return $verified!==null&&$protected&&$authorizer->decide(SCOPE,$verified->account(),'file.share',$target->resource())->allowed();
    });
    $targetFactory=static function(File $file,string $delivery)use($path):Target{return new Target('file.download',$file->resource(),$path,['delivery'=>$delivery,'file_id'=>$file->sourceResource()->id()],$delivery==='redeem'?'POST':'GET');};
    if(isset($_GET['file_id'])||isset($_GET['delivery'])||isset($_GET['_ss'])){
        $id=$_GET['file_id'] ?? null;$delivery=$_GET['delivery'] ?? null;
        if(!is_string($id)||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$id)||!is_string($delivery)||!in_array($delivery,['private','read','once','redeem'],true)){throw new ValidationException('Invalid file request.','download.input');}
        if($delivery==='redeem'&&$method==='GET'){list($csrf,$binding)=startSession($secure);output(200,['redemption'=>true,'csrf'=>$csrf->issue('controls',$binding)]);return;}
        if($delivery==='private'){
            if($method==='POST'){header('Allow: GET, HEAD');output(405,['error'=>'download.method']);return;}
            if(($_SERVER['QUERY_STRING'] ?? '')!==http_build_query(['delivery'=>'private','file_id'=>$id],'','&',PHP_QUERY_RFC3986)){throw new ValidationException('Unexpected private query.','download.input');}
            list($csrf,$binding)=startSession($secure);$subject=$_SESSION['download_subject'] ?? null;$token=$_SESSION['download_session'] ?? null;
            if(!is_string($subject)||!is_string($token)||$sessions->verify(SCOPE,$subject,$token)===null){throw new SecurityException('Current private-download authentication required.','download.denied');}
        }
        // Generic malformed headers have the same response for existing and missing object IDs.
        $requestHeaders=[];foreach(['Range'=>'HTTP_RANGE','If-Range'=>'HTTP_IF_RANGE','If-None-Match'=>'HTTP_IF_NONE_MATCH','If-Modified-Since'=>'HTTP_IF_MODIFIED_SINCE'] as $name=>$serverKey){if(isset($_SERVER[$serverKey])){$requestHeaders[$name]=$_SERVER[$serverKey];}}$request=new Request($method,$requestHeaders);
        $file=currentFile($database,SCOPE,'file',$id);if($file===null){throw new SecurityException('Current file unavailable.','download.denied');}
        if($delivery==='private'){
            $access=new SessionAccess($sessions,$authorizer,SCOPE,$subject,$token,static function(){return true;});
        }else{
            if($delivery==='redeem'){
                list($csrf,$binding)=startSession($secure);if(array_diff(array_keys($_POST),['_csrf'])||!$csrf->verify('controls',$binding,$_POST['_csrf'] ?? null)){throw new SecurityException('Explicit protected redemption required.','download.request_denied');}
            }elseif($method==='POST'){header('Allow: GET, HEAD');output(405,['error'=>'download.method']);return;}
            $readAllowed=true;$access=new LinkAccess($links,static function(File $current)use($targetFactory,$delivery):Target{return $targetFactory($current,$delivery);},$origin.$raw);
        }
        $limit=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_BUDGET_KIB');if($limit!==false&&(!preg_match('/\A[1-9][0-9]{0,6}\z/D',$limit)||(int)$limit>1000000)){throw new \RuntimeException('Invalid byte budget.');}
        $budgets=new BudgetGroup($store,['requests'=>new BudgetPolicy('fixed_window',240,60),'kib'=>new BudgetPolicy('fixed_window',$limit===false?65536:(int)$limit,60)]);$leases=new LeaseManager($store,new LeasePolicy(4,30,30));$resourceAccess=new ResourceAccess($access,$budgets,$leases);
        $root=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_ROOT');$temporary=getenv('SOSECURITY_DOWNLOAD_EXAMPLE_TEMPORARY');if(!$root||!$temporary){throw new \RuntimeException('Configure private source and snapshot directories.');}
        $downloads=new Downloads($root,$temporary,$_SERVER['DOCUMENT_ROOT']);
        if(session_status()===PHP_SESSION_ACTIVE){header('Set-Cookie: '.SessionSecurity::cookieHeader($secure),false);session_write_close();}
        try{
            $transfer=$downloads->prepare($file,$request,$resourceAccess,static function(string $scope,string $type,string $id)use($database):?File{return currentFile($database,$scope,$type,$id);});
            $status=$transfer->status();$headers=$transfer->headers();$streaming=true;http_response_code($status);foreach($headers as $name=>$value){header($name.': '.$value);}
            $transfer->send(static function(string $chunk):int{echo $chunk;if(connection_aborted()){throw new \RuntimeException('Output disconnected.');}return strlen($chunk);});
        }finally{try{if($transfer!==null){$transfer->close();}}finally{$resourceAccess->close();}}return;
    }
    if(($_SERVER['QUERY_STRING'] ?? '')!==''){throw new ValidationException('Unexpected query fields.','download.input');}if($method==='HEAD'){header('Allow: GET, POST');output(405,['error'=>'download.method']);return;}
    list($csrf,$binding)=startSession($secure);$verified=isset($_SESSION['download_subject'],$_SESSION['download_session'])?$sessions->verify(SCOPE,$_SESSION['download_subject'],$_SESSION['download_session']):null;
    $protected=$method==='POST'&&$csrf->verify('controls',$binding,$_POST['_csrf'] ?? null);$flow=new AuthenticationFlow($store,$provider,$sessions,static function()use(&$protected):bool{return $protected;});$extra=[];$status=200;
    if($method==='POST'){
        if(!$protected){throw new SecurityException('Request protection failed.','download.request_denied');}
        $budget=(new \SoSecurity\RateLimit\RateLimiter($store,new \SoSecurity\RateLimit\Policy(80,60,[10],120)))->consume('actions',$ip);if(!$budget->allowed){header('Retry-After: '.$budget->retryAfter);output(429,['error'=>'download.rate']);return;}
        $action=$_POST['action'] ?? null;$fields=['login'=>['username','password'],'logout'=>[],'issue'=>['file_id','delivery'],'revoke'=>['file_id','link_id']];
        if(!is_string($action)||!isset($fields[$action])||array_diff(array_keys($_POST),array_merge(['_csrf','action'],$fields[$action]))){throw new ValidationException('Unexpected control fields.','download.input');}
        if($action==='login'){
            if($verified!==null){throw new SecurityException('Already authenticated.','download.request_denied');}$login=$flow->password(SCOPE,$binding,$_POST['username'] ?? null,$_POST['password'] ?? null);
            if($login->status()!=='authenticated'){$status=401;$extra=['error'=>'download.authentication'];}else{
                $credential=$login->credential();try{(new SessionSecurity())->rotate();}catch(\Throwable $error){$sessions->revoke(SCOPE,$login->account()->subject(),$credential->id());throw $error;}
                $_SESSION['download_subject']=$login->account()->subject();$_SESSION['download_session']=$credential->token();$csrf->revoke('controls',$binding);$binding=bin2hex(random_bytes(32));$_SESSION['download_binding']=$binding;
            }
        }elseif($verified===null){throw new SecurityException('Current authentication required.','download.authentication');}
        elseif($action==='logout'){$sessions->revoke(SCOPE,$verified->account()->subject(),$verified->id());$flow->cancel(SCOPE,$binding);$csrf->revoke('controls',$binding);(new SessionSecurity())->rotate();$binding=bin2hex(random_bytes(32));$_SESSION['download_binding']=$binding;unset($_SESSION['download_subject'],$_SESSION['download_session']);}
        else{
            $id=$_POST['file_id'] ?? null;$delivery=$action==='issue'?($_POST['delivery'] ?? null):'read';if(!is_string($id)||!is_string($delivery)||!in_array($delivery,['read','once','redeem'],true)){throw new ValidationException('Invalid file control.','download.input');}$file=currentFile($database,SCOPE,'file',$id);if($file===null){throw new SecurityException('Current file unavailable.','download.denied');}$target=$targetFactory($file,$delivery);
            if($action==='issue'){$issued=$links->issue($target,$delivery!=='read');$extra=['issued_url'=>$issued->url(),'issued'=>['id'=>$issued->id(),'expires_at'=>$issued->expiresAt(),'one_time'=>$issued->oneTime()]];}
            else{if(!is_string($_POST['link_id'] ?? null)){throw new ValidationException('Invalid link reference.','download.input');}$extra=['revoked'=>$links->revoke($target,$_POST['link_id'])];}
        }
    }
    $verified=isset($_SESSION['download_subject'],$_SESSION['download_session'])?$sessions->verify(SCOPE,$_SESSION['download_subject'],$_SESSION['download_session']):null;if($verified===null){unset($_SESSION['download_subject'],$_SESSION['download_session']);}
    output($status,$extra+['stage'=>$verified===null?'anonymous':'authenticated','csrf'=>$csrf->issue('controls',$binding)]);
}catch(RangeException $error){if($streaming){error_log('download.stream_aborted');}else{if($error->totalBytes()!==null){header('Content-Range: bytes */'.$error->totalBytes());}output($error->totalBytes()===null?400:416,['error'=>'download.range']);}}
catch(ValidationException $error){if($streaming){error_log('download.stream_aborted');}else{output(400,['error'=>'download.input']);}}
catch(SecurityException $error){if($streaming){error_log('download.stream_aborted');}else{
    $reason=$error->reason();$limited=in_array($reason,['download.rate','download.concurrent'],true);$denied=in_array($reason,['download.denied','download.changed','download.version','download.source','download.request_denied','download.authentication','authorization.denied','link.denied','link.request_denied'],true);
    if($limited){header('Retry-After: 60');}output($limited?429:($denied?403:503),['error'=>$limited?'download.rate':($denied?'download.denied':'download.unavailable')]);
}}
catch(\Throwable $error){if($streaming){error_log('download.stream_aborted');}else{output(503,['error'=>'download.unavailable']);}}
