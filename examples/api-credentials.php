<?php
declare(strict_types=1);
namespace SoSecurity\Examples\CredentialHttp;
ini_set('display_errors','0');
$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;
use PDO;
use SoSecurity\Api\CredentialPolicy;
use SoSecurity\Api\CredentialRegistry;
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
use SoSecurity\Output\Escaper;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;
const SCOPE='credential-example';

function output(int $status,array $data,bool $json=false):void
{
    http_response_code($status);header('Cache-Control: no-store, private');header('Referrer-Policy: no-referrer');header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    if(session_status()===PHP_SESSION_ACTIVE){header('Set-Cookie: '.SessionSecurity::cookieHeader(getenv('SOSECURITY_CREDENTIAL_EXAMPLE_HTTPS')!=='0'),false);}
    if($json||strpos($_SERVER['HTTP_ACCEPT'] ?? '','application/json')!==false){header('Content-Type: application/json; charset=utf-8');echo json_encode($data);return;}
    header('Content-Type: text/html; charset=utf-8');echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>API凭据管理</title><style>body{font:16px/1.6 system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem}form{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}label{display:grid;max-width:100%}input,button,select,textarea{font:inherit;max-width:100%;box-sizing:border-box}pre{white-space:pre-wrap;overflow-wrap:anywhere}textarea{width:100%;height:9rem}article{border-top:1px solid #ccc}</style><main><h1>API凭据管理</h1>';
    if(isset($data['issued_token'])){echo '<p>秘密仅本次展示，请复制到客户端的私有配置。刷新后无法重新查询。不要放入网址或日志。</p><textarea data-issued-token readonly aria-label="新凭据秘密">'.Escaper::html($data['issued_token']).'</textarea>';}
    if(isset($data['csrf'])){
        $form='<form method="post"><input type="hidden" name="_csrf" value="'.Escaper::html($data['csrf']).'">';
        if(($data['stage'] ?? '')==='mfa_required'){
            echo $form.'<input type="hidden" name="flow_id" value="'.Escaper::html($data['flow_id']).'"><label>TOTP验证码<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"></label><button name="action" value="second_factor">完成强认证</button></form>';
        }elseif(($data['stage'] ?? '')==='authenticated'){
            echo '<p>当前操作者：'.Escaper::html($data['operator']).'；凭据所属账号：'.Escaper::html($data['owner']).'。退出管理会话不会自动撤销API凭据。</p>';
            echo '<form method="get"><label>目标账号<input name="owner" maxlength="64" value="'.Escaper::html($data['owner']).'"></label><button>查看目标凭据</button></form>';
            echo $form.'<label>名称<input name="name" maxlength="128" required></label><label>权限范围<select name="scopes[]" multiple><option value="documents:read" selected>读取文档</option><option value="documents:write">修改文档标题</option></select></label><button name="action" value="issue">签发凭据</button></form>';
            foreach($data['credentials'] as $row){
                echo '<article><p>'.Escaper::html($row['name']).' · 第'.(int)$row['generation'].'代 · '.Escaper::html(implode(', ',$row['scopes'])).'</p>'.$form.'<input type="hidden" name="id" value="'.Escaper::html($row['id']).'"><input type="hidden" name="generation" value="'.(int)$row['generation'].'"><button name="action" value="rotate">轮换秘密</button><button name="action" value="revoke">撤销</button></form>';
                echo $form.'<input type="hidden" name="id" value="'.Escaper::html($row['id']).'"><input type="hidden" name="generation" value="'.(int)$row['generation'].'"><label>新名称<input name="name" maxlength="128" value="'.Escaper::html($row['name']).'" required></label><label>新范围<select name="scopes[]" multiple><option value="documents:read" selected>读取文档</option><option value="documents:write">修改文档标题</option></select></label><button name="action" value="replace">替换秘密与属性</button></form></article>';
            }
            echo $form.'<button name="action" value="revoke_all">撤销目标全部凭据</button></form>'.$form.'<button name="action" value="logout">退出管理会话</button></form>';
        }else{echo $form.'<label>账号<input name="username" maxlength="256" autocomplete="username"></label><label>密码<input type="password" name="password" maxlength="4096" autocomplete="current-password"></label><button name="action" value="login">登录</button></form>';}
    }
    $display=$data;unset($display['csrf'],$display['issued_token'],$display['flow_id']);echo '<pre data-credential-state>'.Escaper::html(json_encode($display,JSON_PRETTY_PRINT)).'</pre></main></html>';
}
function privateFile(string $name,int $maximum=0):string
{
    $path=getenv($name);$real=$path?realpath($path):false;$web=realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if($real===false||!is_file($real)||is_link($path)||(fileperms($real)&0077)!==0||$web===false||$real===$web||strpos($real,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0||($maximum>0&&filesize($real)>$maximum)){throw new \RuntimeException('Configure a private file outside the web root.');}return $real;
}
function keyConfiguration(string $name):array
{
    $json=file_get_contents(privateFile($name,16384),false,null,0,16385);$data=is_string($json)&&strlen($json)<=16384?json_decode($json,true):null;
    if(!is_array($data)||count($data)!==2||!is_string($data['current'] ?? null)||!is_array($data['keys'] ?? null)){throw new \RuntimeException('Invalid private key configuration.');}$secrets=[];
    foreach($data['keys'] as $id=>$encoded){if(!is_string($encoded)||!is_string($decoded=base64_decode($encoded,true))||base64_encode($decoded)!==$encoded){throw new \RuntimeException('Invalid private key encoding.');}$secrets[$id]=$decoded;}
    return [$data['current'],$secrets];
}
function passwordRecord(PDO $pdo,string $scope,string $value,bool $byUsername=false):?PasswordRecord
{
    if($scope!==SCOPE){return null;}$query=$pdo->prepare('SELECT subject,password_hash,version,enabled,roles,mfa_required,kind FROM credential_accounts WHERE tenant=:tenant AND '.($byUsername?'username':'subject').'=:value');$query->execute(['tenant'=>SCOPE,'value'=>$value]);$row=$query->fetch(PDO::FETCH_ASSOC);if(!is_array($row)){return null;}
    if(!in_array($row['kind'],['user','service'],true)||!is_string($row['roles'])||strlen($row['roles'])>4096||!in_array((string)$row['enabled'],['0','1'],true)||!in_array((string)$row['mfa_required'],['0','1'],true)){throw new \RuntimeException('Invalid account source.');}
    if($byUsername&&$row['kind']!=='user'){return null;}$roles=json_decode($row['roles'],true,4);if(!is_array($roles)||array_values($roles)!==$roles){throw new \RuntimeException('Invalid role source.');}
    return new PasswordRecord(new Account(SCOPE,$row['subject'],$row['version'],(int)$row['enabled']===1,$roles,(int)$row['mfa_required']===1),$row['password_hash']);
}
function identifier($value):string
{
    if(!is_string($value)||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$value)){throw new ValidationException('Expected bounded identifier.','credentials.input');}return $value;
}
function generation($value):int
{
    if(!is_string($value)||!preg_match('/\A[1-9][0-9]{0,18}\z/D',$value)||(string)(int)$value!==$value){throw new ValidationException('Expected canonical generation.','credentials.input');}return (int)$value;
}
function limit(FileStore $store,string $purpose,string $key,int $maximum):void
{
    $decision=(new \SoSecurity\RateLimit\RateLimiter($store,new \SoSecurity\RateLimit\Policy($maximum,60,[10],120)))->consume($purpose,$key);
    if(!$decision->allowed){throw new SecurityException('Request budget exhausted.','credentials.rate');}
}
function currentDocument(PDO $database,string $id,string $owner,string $version):bool
{
    $query=$database->prepare('SELECT 1 FROM credential_documents WHERE tenant=:tenant AND id=:id AND owner=:owner AND version=:version');$query->execute(['tenant'=>SCOPE,'id'=>$id,'owner'=>$owner,'version'=>$version]);return $query->fetchColumn()!==false;
}
$api=false;$database=null;
try{
    $origin=getenv('SOSECURITY_CREDENTIAL_EXAMPLE_ORIGIN');$storage=getenv('SOSECURITY_CREDENTIAL_EXAMPLE_STORAGE');$dummy=getenv('SOSECURITY_CREDENTIAL_EXAMPLE_DUMMY_HASH');$secure=getenv('SOSECURITY_CREDENTIAL_EXAMPLE_HTTPS')!=='0';$path=getenv('SOSECURITY_CREDENTIAL_EXAMPLE_PATH') ?: '/api-credentials.php';
    if(!$origin||!$storage||!$dummy){throw new \RuntimeException('Configure explicit origin, private state and identity source.');}
    // Reuse the library's strict origin parser; no forwarded-header trust is inferred.
    new \SoSecurity\Link\Policy($origin,300,86400,32,!$secure);
    if(($secure&&((strtolower($_SERVER['HTTPS'] ?? '')!=='on'&&($_SERVER['HTTPS'] ?? '')!=='1')||substr($origin,0,8)!=='https://'))||(!$secure&&substr($origin,0,7)!=='http://')||($_SERVER['HTTP_HOST'] ?? '')!==substr($origin,strpos($origin,'//')+2)){throw new \RuntimeException('Transport/Host does not match configured origin.');}
    $raw=$_SERVER['REQUEST_URI'] ?? '';if(strlen($raw)>2048||parse_url($raw,PHP_URL_PATH)!==$path){throw new ValidationException('Invalid raw route.','credentials.input');}
    $method=$_SERVER['REQUEST_METHOD'] ?? 'GET';if(!in_array($method,['GET','POST'],true)){header('Allow: GET, POST');output(405,['error'=>'credentials.method']);return;}
    if(isset($_SERVER['HTTP_TRANSFER_ENCODING'])||isset($_SERVER['TRANSFER_ENCODING'])){throw new ValidationException('Unsupported request framing.','credentials.input');}
    $length=$_SERVER['CONTENT_LENGTH'] ?? '0';if(!is_string($length)||!preg_match('/\A(?:0|[1-9][0-9]{0,4})\z/D',$length)||(int)$length>8192){throw new ValidationException('Request body exceeds budget.','credentials.input');}
    $api=isset($_GET['api']);$ownerQuery=null;
    if($api){$id=identifier($_GET['document_id'] ?? null);if($_GET['api']!=='document'||($_SERVER['QUERY_STRING'] ?? '')!==http_build_query(['api'=>'document','document_id'=>$id],'','&',PHP_QUERY_RFC3986)){throw new ValidationException('Unexpected API query.','credentials.input');}}
    else{if(isset($_GET['owner'])){$ownerQuery=identifier($_GET['owner']);}if(($_SERVER['QUERY_STRING'] ?? '')!==($ownerQuery===null?'':http_build_query(['owner'=>$ownerQuery],'','&',PHP_QUERY_RFC3986))){throw new ValidationException('Unexpected management query.','credentials.input');}}
    $storageRoot=realpath($storage);$web=realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);if($storageRoot===false||$storageRoot!==rtrim($storage,'/')||$web===false||$storageRoot===$web||strpos($storageRoot,rtrim($web,'/').'/')===0){throw new \RuntimeException('Configure canonical private state outside the web root.');}
    $store=new FileStore($storageRoot,'credential-example');$ip=(new \SoSecurity\Http\ClientIp())->resolve($_SERVER);limit($store,'entry',$ip,240);
    $database=new PDO('sqlite:'.privateFile('SOSECURITY_CREDENTIAL_EXAMPLE_DATABASE'),null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
    list($current,$secrets)=keyConfiguration('SOSECURITY_CREDENTIAL_EXAMPLE_KEYS');$keys=new \SoSecurity\Support\HmacKeys($current,$secrets);
    $provider=new PasswordIdentityProvider(function(string $scope,string $username)use($database){return passwordRecord($database,$scope,$username,true);},function(string $scope,string $subject)use($database){return passwordRecord($database,$scope,$subject);},new \SoSecurity\Password\PasswordHasher(),$dummy);
    $factor=null;if(getenv('SOSECURITY_CREDENTIAL_EXAMPLE_MFA_KEYS')!==false){list($mfaCurrent,$mfaSecrets)=keyConfiguration('SOSECURITY_CREDENTIAL_EXAMPLE_MFA_KEYS');$factor=new \SoSecurity\Auth\TotpSecondFactor(new \SoSecurity\Mfa\TotpFactors($store,new \SoSecurity\Crypto\Cipher($mfaCurrent,$mfaSecrets,'credential-example:mfa'),'Credential example'));}
    $sessions=new SessionRegistry($store,$provider,$factor);$rules=[];foreach(['issue','all','rotate','replace','revoke','revoke_all'] as $op){$rules['api.credentials.'.$op]=['type'=>'api_credential_owner','roles'=>['admin'],'fields'=>[]];}
    $rules['documents.read']=['type'=>'document','roles'=>['reader','editor'],'fields'=>[],'owner_attribute'=>'owner'];$rules['documents.write']=['type'=>'document','roles'=>['editor'],'fields'=>['title'],'owner_attribute'=>'owner'];$authority=new Authorizer($provider,new RolePolicy($rules));
    $protected=false;$operator=null;$verified=null;
    $ttl=getenv('SOSECURITY_CREDENTIAL_EXAMPLE_TTL');if($ttl!==false&&(!preg_match('/\A[1-9][0-9]{0,7}\z/D',$ttl)||(int)$ttl>31536000)){throw new \RuntimeException('Invalid credential lifetime.');}
    $registry=new CredentialRegistry($store,$sessions,$provider,$keys,SCOPE,static function(string $operation)use(&$protected,$api,$method):bool{return $operation==='authenticate'?$api:(!$api&&($operation==='all'&&$method==='GET'||$protected));},static function(Account $owner):array{
        if(in_array('editor',$owner->roles(),true)){return ['documents:read','documents:write'];}return in_array('reader',$owner->roles(),true)?['documents:read']:[];
    },new CredentialPolicy(['allowed_scopes'=>['documents:read','documents:write'],'ttl'=>$ttl===false?86400:(int)$ttl]),null,$factor,$authority,static function()use(&$operator):string{if(!is_string($operator)){throw new \RuntimeException('Current operator required.');}return $operator;});
    if($api){
        // Bearer routes never start/read a browser Session and never fall back to a Cookie.
        $required=$method==='GET'?'documents:read':'documents:write';$header=$_SERVER['HTTP_AUTHORIZATION'] ?? null;$proof=$registry->fromAuthorization(SCOPE,$header,$required);if($proof===null){throw new SecurityException('Bearer proof required.','credentials.denied');}limit($store,'api-owner',$proof->account()->subject(),60);
        $query=$database->prepare('SELECT owner,version FROM credential_documents WHERE tenant=:tenant AND id=:id');$query->execute(['tenant'=>SCOPE,'id'=>$id]);$metadata=$query->fetch(PDO::FETCH_ASSOC);if(!is_array($metadata)){throw new SecurityException('Document unavailable.','credentials.denied');}$resource=new Resource(SCOPE,'document',$id,$metadata['version'],['owner'=>$metadata['owner']]);$action=$method==='GET'?'documents.read':'documents.write';$fields=$method==='GET'?[]:['title'];$authority->assertAllowed(SCOPE,$proof->account(),$action,$resource,$fields);
        if($method==='POST'){
            if(strtolower(trim(explode(';',$_SERVER['CONTENT_TYPE'] ?? '')[0]))!=='application/json'){throw new ValidationException('Expected bounded JSON.','credentials.input');}$body=file_get_contents('php://input',false,null,0,8193);$input=is_string($body)&&strlen($body)<=8192?json_decode($body,true,4):null;
            if(!is_array($input)||count($input)!==2||!is_string($input['title'] ?? null)||!is_string($input['version'] ?? null)||$input['title']===''||strlen($input['title'])>256||!preg_match('//u',$input['title'])||preg_match('/[\x00-\x1f\x7f]/',$input['title'])||!hash_equals($metadata['version'],$input['version'])){throw new ValidationException('Invalid document update.','credentials.input');}
            $database->beginTransaction();$next=bin2hex(random_bytes(16));$query=$database->prepare('UPDATE credential_documents SET title=:title,version=:next WHERE tenant=:tenant AND id=:id AND owner=:owner AND version=:version');$query->execute(['title'=>$input['title'],'next'=>$next,'tenant'=>SCOPE,'id'=>$id,'owner'=>$metadata['owner'],'version'=>$metadata['version']]);if($query->rowCount()!==1){throw new SecurityException('Document changed.','credentials.denied');}
            $fresh=$registry->fromAuthorization(SCOPE,$header,$required);if($fresh===null||!hash_equals($proof->account()->fingerprint(),$fresh->account()->fingerprint())){throw new SecurityException('Bearer changed during write.','credentials.denied');}$authority->assertAllowed(SCOPE,$fresh->account(),$action,$resource,$fields);if(time()>=$fresh->expiresAt()){throw new SecurityException('Bearer expired.','credentials.denied');}$database->commit();output(200,['updated'=>true,'version'=>$next],true);return;
        }
        $query=$database->prepare('SELECT title,body FROM credential_documents WHERE tenant=:tenant AND id=:id AND owner=:owner AND version=:version AND length(CAST(title AS BLOB))<=256 AND length(CAST(body AS BLOB))<=8192');$query->execute(['tenant'=>SCOPE,'id'=>$id,'owner'=>$metadata['owner'],'version'=>$metadata['version']]);$document=$query->fetch(PDO::FETCH_ASSOC);
        if(!is_array($document)||!is_string($document['title'])||!is_string($document['body'])||strlen($document['title'])>256||strlen($document['body'])>8192||!preg_match('//u',$document['title'].$document['body'])){throw new SecurityException('Document unavailable.','credentials.denied');}
        $fresh=$registry->fromAuthorization(SCOPE,$header,$required);if($fresh===null||!hash_equals($proof->account()->fingerprint(),$fresh->account()->fingerprint())){throw new SecurityException('Bearer changed during read.','credentials.denied');}$authority->assertAllowed(SCOPE,$fresh->account(),$action,$resource);if(!currentDocument($database,$id,$metadata['owner'],$metadata['version'])||time()>=$fresh->expiresAt()){throw new SecurityException('Bearer or document changed.','credentials.denied');}output(200,['document'=>$document,'version'=>$metadata['version']],true);return;
    }
    SessionSecurity::configure($secure);session_name('SoSecurityCredentialExample');ini_set('session.cookie_path',rtrim(str_replace('\\','/',dirname($_SERVER['SCRIPT_NAME'] ?? '/')),'/.').'/');if(!session_start()){throw new \RuntimeException('Cannot start protected management session.');}
    if(!isset($_SESSION['credential_binding'])){$_SESSION['credential_binding']=bin2hex(random_bytes(32));}$binding=$_SESSION['credential_binding'];$csrf=new CsrfTokens(new SessionStore('credential-controls'));$csrfScope='controls:'.hash('sha256',$ownerQuery ?? '');
    $operator=$_SESSION['credential_subject'] ?? null;$sessionToken=$_SESSION['credential_session'] ?? null;if(is_string($operator)&&is_string($sessionToken)){$verified=$sessions->verify(SCOPE,$operator,$sessionToken);}if($verified===null){unset($_SESSION['credential_subject'],$_SESSION['credential_session']);$operator=null;}
    $protected=$method==='POST'&&$csrf->verify($csrfScope,$binding,$_POST['_csrf'] ?? null);$flow=new AuthenticationFlow($store,$provider,$sessions,static function()use(&$protected):bool{return $protected;},$factor);$extra=[];$status=200;
    if($method==='POST'){
        if(!$protected){throw new SecurityException('Request protection failed.','credentials.denied');}limit($store,'actions',$ip,80);
        $action=$_POST['action'] ?? null;$fields=['login'=>['username','password'],'second_factor'=>['flow_id','code'],'logout'=>[],'issue'=>['name','scopes'],'rotate'=>['id','generation'],'replace'=>['id','generation','name','scopes'],'revoke'=>['id','generation'],'revoke_all'=>[]];
        if(!is_string($action)||!isset($fields[$action])||array_diff(array_keys($_POST),array_merge(['action','_csrf'],$fields[$action]))){throw new ValidationException('Unexpected management fields.','credentials.input');}
        if($action==='login'||$action==='second_factor'){
            if($verified!==null){throw new SecurityException('Already authenticated.','credentials.denied');}
            if($action==='login'){$login=$flow->password(SCOPE,$binding,$_POST['username'] ?? null,$_POST['password'] ?? null);unset($_SESSION['credential_pending']);}
            else{$pending=$_SESSION['credential_pending'] ?? null;if(!is_string($pending)||!is_string($_POST['flow_id'] ?? null)||!hash_equals(hash('sha256',$pending),$_POST['flow_id'])){throw new SecurityException('Pending login changed.','credentials.denied');}$login=$flow->secondFactor(SCOPE,$binding,$pending,['type'=>'totp','code'=>$_POST['code'] ?? null]);}
            if($login->status()==='mfa_required'){$_SESSION['credential_pending']=$login->challenge();}
            elseif($login->status()==='authenticated'){
                $credential=$login->credential();try{(new SessionSecurity())->rotate();}catch(\Throwable $error){$sessions->revoke(SCOPE,$login->account()->subject(),$credential->id());throw $error;}
                $csrf->revoke($csrfScope,$binding);$binding=bin2hex(random_bytes(32));$_SESSION['credential_binding']=$binding;$_SESSION['credential_subject']=$login->account()->subject();$_SESSION['credential_session']=$credential->token();unset($_SESSION['credential_pending']);$operator=$login->account()->subject();$sessionToken=$credential->token();$verified=$sessions->verify(SCOPE,$operator,$sessionToken);
            }else{$status=401;$extra=['error'=>'credentials.authentication'];}
        }elseif($verified===null){throw new SecurityException('Current management session required.','credentials.denied');}
        elseif($action==='logout'){$sessions->revoke(SCOPE,$operator,$verified->id());$flow->cancel(SCOPE,$binding);$csrf->revoke($csrfScope,$binding);(new SessionSecurity())->rotate();$binding=bin2hex(random_bytes(32));$_SESSION['credential_binding']=$binding;unset($_SESSION['credential_subject'],$_SESSION['credential_session'],$_SESSION['credential_pending']);$operator=null;$verified=null;}
        else{
            $owner=$ownerQuery ?? $operator;$issued=null;
            if($action==='issue'||$action==='replace'){
                if(!is_string($_POST['name'] ?? null)||!is_array($_POST['scopes'] ?? null)){throw new ValidationException('Expected name and scopes.','credentials.input');}
                $issued=$action==='issue'?$registry->issue(SCOPE,$owner,$sessionToken,$_POST['name'],$_POST['scopes']):$registry->replace(SCOPE,$owner,$sessionToken,$_POST['id'] ?? '',generation($_POST['generation'] ?? null),$_POST['name'],$_POST['scopes']);
            }elseif($action==='rotate'){$issued=$registry->rotate(SCOPE,$owner,$sessionToken,$_POST['id'] ?? '',generation($_POST['generation'] ?? null));}
            elseif($action==='revoke'){if(!is_string($_POST['id'] ?? null)){throw new ValidationException('Expected credential ID.','credentials.input');}$extra=['revoked'=>$registry->revoke(SCOPE,$owner,$sessionToken,$_POST['id'])];}
            else{$extra=['revoked_count'=>$registry->revokeAll(SCOPE,$owner,$sessionToken)];}
            if($issued!==null){$extra=['issued_token'=>$issued->token(),'issued'=>$issued->metadata()->toArray()];}elseif($action==='rotate'||$action==='replace'){$status=409;$extra=['error'=>'credentials.conflict'];}
        }
    }
    $pending=$_SESSION['credential_pending'] ?? null;$data=['stage'=>$verified!==null?'authenticated':(is_string($pending)?'mfa_required':'anonymous'),'csrf'=>$csrf->issue($csrfScope,$binding)];
    if(is_string($pending)){$data['flow_id']=hash('sha256',$pending);}if($verified!==null){$owner=$ownerQuery ?? $operator;$data+=['operator'=>$operator,'owner'=>$owner,'credentials'=>array_map(static function($info):array{return $info->toArray();},$registry->all(SCOPE,$owner,$sessionToken))];}output($status,$extra+$data);
}catch(ValidationException $error){if($database instanceof PDO&&$database->inTransaction()){$database->rollBack();}output(400,['error'=>'credentials.input'],$api);}
catch(SecurityException $error){if($database instanceof PDO&&$database->inTransaction()){$database->rollBack();}$limited=$error->reason()==='credentials.rate';$denied=in_array($error->reason(),['credentials.denied','authorization.denied','api_credentials.denied','api_credentials.reauthentication','api_credentials.scope_denied'],true);if($limited){header('Retry-After: 60');}output($limited?429:($denied?403:503),['error'=>$limited?'credentials.rate':($denied?'credentials.denied':'credentials.unavailable')],$api);}
catch(\Throwable $error){if($database instanceof PDO&&$database->inTransaction()){$database->rollBack();}output(503,['error'=>'credentials.unavailable'],$api);}
