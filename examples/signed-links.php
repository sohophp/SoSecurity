<?php
declare(strict_types=1);
namespace SoSecurity\Examples\LinkHttp;
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
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Link\Links;
use SoSecurity\Link\Policy;
use SoSecurity\Link\Target;
use SoSecurity\Output\Escaper;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;
const SCOPE='link-example';
function output(int $status,array $data):void
{
    http_response_code($status);header('Cache-Control: no-store, private');header('Referrer-Policy: no-referrer');header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    if(session_status()===PHP_SESSION_ACTIVE){header('Set-Cookie: '.SessionSecurity::cookieHeader(getenv('SOSECURITY_LINK_EXAMPLE_HTTPS')!=='0'),false);}
    if(strpos($_SERVER['HTTP_ACCEPT'] ?? '','application/json')!==false){header('Content-Type: application/json; charset=utf-8');echo json_encode($data);return;}
    header('Content-Type: text/html; charset=utf-8');echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>签名链接示例</title><style>body{font:16px/1.6 system-ui;max-width:44rem;margin:2rem auto;padding:0 1rem}form{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}label{display:grid;max-width:100%}input,button,select{font:inherit;max-width:100%;box-sizing:border-box}pre,a{white-space:pre-wrap;overflow-wrap:anywhere}section{padding:1rem;border:1px solid #aaa}</style><main><h1>签名链接示例</h1>';
    if(isset($data['content'])){echo '<section data-content><h2>'.Escaper::html($data['content']['title']).'</h2><p>'.Escaper::html($data['content']['body']).'</p></section>';}
    if(isset($data['issued_url'])){echo '<p>请妥善保存此链接；持有未绑定链接的人可以读取其授权内容。</p><a data-issued-link href="'.Escaper::html($data['issued_url']).'">'.Escaper::html($data['issued_url']).'</a>';}
    if(isset($data['csrf'])){
        $form='<form method="post"><input type="hidden" name="_csrf" value="'.Escaper::html($data['csrf']).'">';
        if(!empty($data['redemption'])){echo '<p>此页尚未兑换或读取正文。提交后将消费一次授权，重复提交无效。</p>'.$form.'<button>明确兑换并读取</button></form>';}
        elseif(($data['stage'] ?? '')==='authenticated'){
            echo $form.'<label>文档编号<input name="document_id" value="a" maxlength="64"></label><label>读取方式<select name="delivery"><option value="read">期限内重复读取</option><option value="once">一次GET（可能被预取消耗）</option><option value="redeem">明确POST兑换一次</option></select></label><button name="action" value="issue">签发链接</button></form>';
            echo $form.'<label>文档编号<input name="document_id" value="a" maxlength="64"></label><label>链接编号<input name="link_id" maxlength="32"></label><button name="action" value="revoke">撤销此链接</button></form>';
            echo $form.'<label>文档编号<input name="document_id" value="a" maxlength="64"></label><button name="action" value="list">查询元数据</button><button name="action" value="revoke_all">撤销此文档全部链接</button></form>'.$form.'<button name="action" value="logout">退出</button></form>';
        }else{echo $form.'<label>账号<input name="username" maxlength="256" autocomplete="username"></label><label>密码<input type="password" name="password" maxlength="4096" autocomplete="current-password"></label><button name="action" value="login">登录签发账号</button></form>';}
    }
    $display=$data;unset($display['csrf'],$display['issued_url']);echo '<pre data-link-state>'.Escaper::html(json_encode($display,JSON_PRETTY_PRINT)).'</pre></main></html>';
}
function privateFile(string $name,int $maximum=0):string
{
    $path=getenv($name);$real=$path?realpath($path):false;$web=realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if($real===false||!is_file($real)||is_link($path)||(fileperms($real)&0077)!==0||$web===false||$real===$web||strpos($real,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0||($maximum>0&&filesize($real)>$maximum)){throw new \RuntimeException('Configure a private file outside the web root.');}return $real;
}
function passwordRecord(PDO $pdo,string $scope,string $value,bool $byUsername=false):?PasswordRecord
{
    if($scope!==SCOPE){return null;}$query=$pdo->prepare('SELECT subject,password_hash,version,enabled,roles FROM link_accounts WHERE tenant=:tenant AND '.($byUsername?'username':'subject').'=:value');$query->execute(['tenant'=>SCOPE,'value'=>$value]);$row=$query->fetch(PDO::FETCH_ASSOC);if(!is_array($row)){return null;}
    if(!is_string($row['roles'])||strlen($row['roles'])>4096||!in_array((string)$row['enabled'],['0','1'],true)){throw new \RuntimeException('Invalid account source.');}$roles=json_decode($row['roles'],true,4);
    if(!is_array($roles)||array_values($roles)!==$roles){throw new \RuntimeException('Invalid role source.');}return new PasswordRecord(new Account(SCOPE,$row['subject'],$row['version'],(int)$row['enabled']===1,$roles),$row['password_hash']);
}
/** Metadata only. Private title/body are read only after verification with version/account predicates. */
function currentTarget(PDO $pdo,string $id,string $delivery,string $path):array
{
    if(!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$id)||!in_array($delivery,['read','once','redeem'],true)){throw new ValidationException('Invalid resource request.','link.input');}
    $query=$pdo->prepare('SELECT owner,version FROM link_documents WHERE tenant=:tenant AND id=:id');$query->execute(['tenant'=>SCOPE,'id'=>$id]);$row=$query->fetch(PDO::FETCH_ASSOC);$owner=is_array($row)?passwordRecord($pdo,SCOPE,$row['owner']):null;
    if($owner===null||!$owner->account()->enabled()){throw new SecurityException('Link resource unavailable.','link.denied');}
    $resource=new Resource(SCOPE,'document',$id,(string)$row['version'],['owner'=>$owner->account()->subject(),'owner_identity'=>$owner->identity()->fingerprint()]);
    return [new Target('document.read',$resource,$path,['delivery'=>$delivery,'document_id'=>$id],$delivery==='redeem'?'POST':'GET'),$owner];
}
function startSession(bool $secure):array
{
    SessionSecurity::configure($secure);session_name('SoSecurityLinkExample');ini_set('session.cookie_path',rtrim(str_replace('\\','/',dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/.').'/');
    if(!session_start()){throw new \RuntimeException('Cannot start protected host session.');}
    if(!isset($_SESSION['link_binding'])){$_SESSION['link_binding']=bin2hex(random_bytes(32));}
    return [new CsrfTokens(new SessionStore('link-controls')),$_SESSION['link_binding']];
}
try{
    $database=new PDO('sqlite:'.privateFile('SOSECURITY_LINK_EXAMPLE_DATABASE'),null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
    $keysJson=file_get_contents(privateFile('SOSECURITY_LINK_EXAMPLE_KEYS',16384),false,null,0,16385);if(!is_string($keysJson)||strlen($keysJson)>16384){throw new \RuntimeException('Invalid signing configuration size.');}
    $keysData=json_decode($keysJson,true);if(!is_array($keysData)||count($keysData)!==2||!is_string($keysData['current'] ?? null)||!is_array($keysData['keys'] ?? null)){throw new \RuntimeException('Invalid signing configuration.');}$secrets=[];
    foreach($keysData['keys'] as $id=>$encoded){if(!is_string($encoded)||!is_string($decoded=base64_decode($encoded,true))||base64_encode($decoded)!==$encoded){throw new \RuntimeException('Invalid signing key.');}$secrets[$id]=$decoded;}$keys=new \SoSecurity\Support\HmacKeys($keysData['current'],$secrets);
    $origin=getenv('SOSECURITY_LINK_EXAMPLE_ORIGIN');$storage=getenv('SOSECURITY_LINK_EXAMPLE_STORAGE');$dummy=getenv('SOSECURITY_LINK_EXAMPLE_DUMMY_HASH');$secure=getenv('SOSECURITY_LINK_EXAMPLE_HTTPS')!=='0';$path=getenv('SOSECURITY_LINK_EXAMPLE_PATH') ?: '/signed-links.php';
    if(!$origin||!$storage||!$dummy){throw new \RuntimeException('Configure explicit origin, storage and credential source.');}$policy=new Policy($origin,300,86400,32,!$secure);
    if(($secure&&((strtolower($_SERVER['HTTPS'] ?? '')!=='on'&&($_SERVER['HTTPS'] ?? '')!=='1')||substr($origin,0,8)!=='https://'))||(!$secure&&substr($origin,0,7)!=='http://')||($_SERVER['HTTP_HOST'] ?? '')!==substr($origin,strpos($origin,'//')+2)){throw new \RuntimeException('Trusted transport/Host does not match signing origin.');}
    $raw=$_SERVER['REQUEST_URI'] ?? '';if(strlen($raw)>2048||parse_url($raw,PHP_URL_PATH)!==$path){throw new ValidationException('Invalid raw route.','link.input');}$method=$_SERVER['REQUEST_METHOD'] ?? 'GET';
    if(!in_array($method,['GET','POST'],true)){header('Allow: GET, POST');output(405,['error'=>'link.method']);return;}
    $store=new FileStore($storage,'link-example');$ip=(new \SoSecurity\Http\ClientIp())->resolve($_SERVER);$entry=(new \SoSecurity\RateLimit\RateLimiter($store,new \SoSecurity\RateLimit\Policy(120,60,[10],120)))->consume('entry',$ip);
    if(!$entry->allowed){header('Retry-After: '.$entry->retryAfter);output(429,['error'=>'link.rate']);return;}
    $provider=new PasswordIdentityProvider(function(string $scope,string $username)use($database){return passwordRecord($database,$scope,$username,true);},function(string $scope,string $subject)use($database){return passwordRecord($database,$scope,$subject);},new \SoSecurity\Password\PasswordHasher(),$dummy);
    $sessions=new SessionRegistry($store,$provider);$authorizer=new Authorizer($provider,new RolePolicy(['document.share'=>['type'=>'document','roles'=>['editor'],'fields'=>[],'owner_attribute'=>'owner']]));
    $verified=null;$protected=false;$readAllowed=false;$csrf=null;$binding='';
    $guard=function(string $operation,Target $target,string $requestMethod)use(&$verified,&$protected,&$readAllowed,$authorizer,$method):bool{
        if($operation==='verify'){return $readAllowed&&$requestMethod===$method;}
        if($verified===null||!$protected){return false;}return $authorizer->decide(SCOPE,$verified->account(),'document.share',$target->resource())->allowed();
    };
    $links=new Links($store,$keys,SCOPE,$policy,$guard);
    if(isset($_GET['document_id'])||isset($_GET['delivery'])||isset($_GET['_ss'])){
        if(!is_string($_GET['document_id'] ?? null)||!is_string($_GET['delivery'] ?? null)){throw new ValidationException('Invalid resource request.','link.input');}
        if($_GET['delivery']==='redeem'&&$method==='GET'){
            if(!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$_GET['document_id'])){throw new ValidationException('Invalid resource request.','link.input');}
            list($csrf,$binding)=startSession($secure);output(200,['redemption'=>true,'csrf'=>$csrf->issue('controls',$binding)]);return;
        }
        list($target,$owner)=currentTarget($database,$_GET['document_id'],$_GET['delivery'],$path);
        if($target->method()==='POST'){
            list($csrf,$binding)=startSession($secure);
            if(array_diff(array_keys($_POST),['_csrf'])||!$csrf->verify('controls',$binding,$_POST['_csrf'] ?? null)){throw new SecurityException('Protected explicit redemption required.','link.request_denied');}
        }elseif($method!=='GET'){header('Allow: GET');output(405,['error'=>'link.method']);return;}
        $readAllowed=true;$proof=$links->verify($target,$origin.$raw,$method);
        if($proof===null){throw new SecurityException('Signed link not accepted.','link.denied');}
        $resource=$target->resource();$query=$database->prepare('SELECT d.title,d.body FROM link_documents d JOIN link_accounts a ON a.tenant=d.tenant AND a.subject=d.owner WHERE d.tenant=:tenant AND d.id=:id AND d.owner=:owner AND d.version=:version AND a.version=:account_version AND a.password_hash=:hash AND a.enabled=1');
        $query->execute(['tenant'=>SCOPE,'id'=>$resource->id(),'owner'=>$owner->account()->subject(),'version'=>$resource->version(),'account_version'=>$owner->account()->version(),'hash'=>$owner->hash()]);$content=$query->fetch(PDO::FETCH_ASSOC);
        if(!is_array($content)||time()>=$proof->expiresAt()){throw new SecurityException('Resource changed or link expired while reading.','link.denied');}
        output(200,['content'=>$content,'link'=>['id'=>$proof->id(),'one_time'=>$proof->oneTime(),'expires_at'=>$proof->expiresAt()]]);return;
    }
    if(($_SERVER['QUERY_STRING'] ?? '')!==''){throw new ValidationException('Unexpected query fields.','link.input');}list($csrf,$binding)=startSession($secure);
    $verified=isset($_SESSION['link_subject'],$_SESSION['link_session'])?$sessions->verify(SCOPE,$_SESSION['link_subject'],$_SESSION['link_session']):null;
    $protected=$method==='POST'&&$csrf->verify('controls',$binding,$_POST['_csrf'] ?? null);$flow=new AuthenticationFlow($store,$provider,$sessions,static function()use(&$protected):bool{return $protected;});$extra=[];$status=200;
    if($method==='POST'){
        if(!$protected){throw new SecurityException('Request protection failed.','link.request_denied');}
        $budget=(new \SoSecurity\RateLimit\RateLimiter($store,new \SoSecurity\RateLimit\Policy(80,60,[10],120)))->consume('actions',$ip);if(!$budget->allowed){header('Retry-After: '.$budget->retryAfter);output(429,['error'=>'link.rate']);return;}
        $action=$_POST['action'] ?? null;$fields=['login'=>['username','password'],'logout'=>[],'issue'=>['document_id','delivery'],'list'=>['document_id'],'revoke'=>['document_id','link_id'],'revoke_all'=>['document_id']];
        if(!is_string($action)||!isset($fields[$action])||array_diff(array_keys($_POST),array_merge(['_csrf','action'],$fields[$action]))){throw new ValidationException('Unexpected control fields.','link.input');}
        if($action==='login'){
            if($verified!==null){throw new SecurityException('Already authenticated.','link.request_denied');}$login=$flow->password(SCOPE,$binding,$_POST['username'] ?? null,$_POST['password'] ?? null);
            if($login->status()!=='authenticated'){$status=401;$extra=['error'=>'link.authentication'];}else{
                $credential=$login->credential();try{(new SessionSecurity())->rotate();}catch(\Throwable $error){$sessions->revoke(SCOPE,$login->account()->subject(),$credential->id());throw $error;}
                $_SESSION['link_subject']=$login->account()->subject();$_SESSION['link_session']=$credential->token();$csrf->revoke('controls',$binding);$binding=bin2hex(random_bytes(32));$_SESSION['link_binding']=$binding;
            }
        }elseif($verified===null){throw new SecurityException('Current issuer authentication required.','link.authentication');}
        elseif($action==='logout'){$sessions->revoke(SCOPE,$verified->account()->subject(),$verified->id());$flow->cancel(SCOPE,$binding);$csrf->revoke('controls',$binding);(new SessionSecurity())->rotate();$binding=bin2hex(random_bytes(32));$_SESSION['link_binding']=$binding;unset($_SESSION['link_subject'],$_SESSION['link_session']);}
        else{
            if(!is_string($_POST['document_id'] ?? null)){throw new ValidationException('Invalid document.','link.input');}$delivery=$action==='issue'?($_POST['delivery'] ?? null):'read';if(!is_string($delivery)){throw new ValidationException('Invalid delivery.','link.input');}list($target)=currentTarget($database,$_POST['document_id'],$delivery,$path);
            if($action==='issue'){$ttl=getenv('SOSECURITY_LINK_EXAMPLE_TTL');if($ttl!==false&&(!preg_match('/\A[1-9][0-9]{0,4}\z/D',$ttl)||(int)$ttl>86400)){throw new \RuntimeException('Invalid configured lifetime.');}$issued=$links->issue($target,$delivery!=='read',$ttl===false?null:(int)$ttl);$extra=['issued_url'=>$issued->url(),'issued'=>['id'=>$issued->id(),'expires_at'=>$issued->expiresAt(),'one_time'=>$issued->oneTime()]];}
            elseif($action==='list'){$extra=['links'=>$links->all($target)];}
            elseif($action==='revoke'){if(!is_string($_POST['link_id'] ?? null)){throw new ValidationException('Invalid link reference.','link.input');}$extra=['revoked'=>$links->revoke($target,$_POST['link_id'])];}
            else{$links->revokeAll($target);$extra=['revoked_all'=>true];}
        }
    }
    $verified=isset($_SESSION['link_subject'],$_SESSION['link_session'])?$sessions->verify(SCOPE,$_SESSION['link_subject'],$_SESSION['link_session']):null;if($verified===null){unset($_SESSION['link_subject'],$_SESSION['link_session']);}
    output($status,$extra+['stage'=>$verified===null?'anonymous':'authenticated','csrf'=>$csrf->issue('controls',$binding)]);
}catch(ValidationException $error){output(400,['error'=>'link.input']);}
catch(SecurityException $error){$reason=$error->reason();$denied=in_array($reason,['link.denied','link.request_denied','link.authentication','authorization.denied'],true);output($denied?403:503,['error'=>$denied?'link.denied':'link.unavailable']);}
catch(\Throwable $error){output(503,['error'=>'link.unavailable']);}
