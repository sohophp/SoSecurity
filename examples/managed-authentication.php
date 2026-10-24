<?php
declare(strict_types=1);

// The private bootstrap returns Security, or Security/state_policy with an optional exact business PDO.
// This example owns only request/session handling; it never provisions an account or factor.
ini_set('display_errors', '0');
require dirname(__DIR__).'/vendor/autoload.php';

use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Output\Escaper;
use SoSecurity\RateLimit\Policy;
use SoSecurity\RateLimit\RateLimiter;
use SoSecurity\Security;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;

function managedResponse(int $status,array $data,bool $json=false):void
{
    http_response_code($status);
    header('Cache-Control: no-store');header('Pragma: no-cache');
    header('Referrer-Policy: no-referrer');header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    if(session_status()===PHP_SESSION_ACTIVE){header('Set-Cookie: '.SessionSecurity::cookieHeader(getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_HTTP')!=='1'),false);}
    if($json||strpos($_SERVER['HTTP_ACCEPT']??'','text/html')===false){header('Content-Type: application/json; charset=utf-8');echo json_encode($data);return;}
    // Same-origin form POSTs need their real Origin; JSON responses keep no-referrer.
    header('Referrer-Policy: same-origin');header('Content-Type: text/html; charset=utf-8');
    $csrf=Escaper::html($data['csrf']??'');$stage=$data['stage']??'unavailable';
    echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>账号登录</title><main><h1>账号登录</h1>';
    if($stage==='anonymous'){
        echo '<form method="post"><input type="hidden" name="_csrf" value="'.$csrf.'"><label>账号<input name="username" autocomplete="username" required></label><label>密码<input type="password" name="password" autocomplete="current-password" required></label><button name="action" value="login">登录</button></form>';
    }elseif($stage==='mfa_required'){
        echo '<form method="post"><input type="hidden" name="_csrf" value="'.$csrf.'"><label>验证码或恢复码<input name="proof" autocomplete="one-time-code" required></label><select name="type"><option value="totp">TOTP</option><option value="recovery">恢复码</option></select><button name="action" value="mfa">完成验证</button></form>';
    }elseif($stage==='authenticated'){
        echo '<form method="post"><input type="hidden" name="_csrf" value="'.$csrf.'"><button name="action" value="logout">退出</button></form>';
    }
    if(isset($data['error'])){echo '<p role="alert">操作未完成</p>';}
    echo '</main></html>';
}

/** Flat, bounded form grammar. Reject duplicate/aliased names instead of depending on PHP's last-value parser. */
function managedForm(int $length):array
{
    if(strtolower(trim(explode(';',$_SERVER['CONTENT_TYPE']??'')[0]))!=='application/x-www-form-urlencoded'){throw new \SoSecurity\Exception\ValidationException('Use an encoded form.','auth.input');}
    $raw=file_get_contents('php://input',false,null,0,8193);if(!is_string($raw)||strlen($raw)!==$length||preg_match('/%(?![a-fA-F0-9]{2})/',$raw)){throw new \SoSecurity\Exception\ValidationException('Invalid bounded form.','auth.input');}
    $parts=explode('&',$raw);if(count($parts)>16){throw new \SoSecurity\Exception\ValidationException('Too many fields.','auth.input');}$form=[];
    foreach($parts as $part){$pair=explode('=',$part,2);if(count($pair)!==2){throw new \SoSecurity\Exception\ValidationException('Invalid form field.','auth.input');}$name=urldecode($pair[0]);$value=urldecode($pair[1]);if(!preg_match('/\A_?[a-z][a-z0-9_]{0,31}\z/D',$name)||array_key_exists($name,$form)||!preg_match('//u',$value)){throw new \SoSecurity\Exception\ValidationException('Duplicate or invalid form field.','auth.input');}$form[$name]=$value;}return $form;
}
function managedInteger(string $value,int $maximum):int
{
    if(!preg_match('/\A[1-9][0-9]{0,18}\z/D',$value)||(string)(int)$value!==$value||(int)$value>$maximum){throw new \SoSecurity\Exception\ValidationException('Use a bounded integer.','auth.input');}return (int)$value;
}
$api=false;$apiAction=false;$business=false;
try{
    $method=$_SERVER['REQUEST_METHOD']??'GET';$query=$_SERVER['QUERY_STRING']??'';$business=$query==='api=document';$api=$business||$query==='api=identity';
    if($query!==''&&!$api){throw new \SoSecurity\Exception\ValidationException('Unexpected query.','auth.input');}
    if(!in_array($method,$api?($business?['POST']:['GET']):['GET','POST'],true)){header('Allow: '.($api?($business?'POST':'GET'):'GET, POST'));managedResponse(405,['error'=>'auth.method'],$api);return;}
    if(isset($_SERVER['HTTP_TRANSFER_ENCODING'])||isset($_SERVER['TRANSFER_ENCODING'])){throw new \SoSecurity\Exception\ValidationException('Unsupported framing.','auth.input');}
    $length=$_SERVER['CONTENT_LENGTH']??'0';if(!is_string($length)||!preg_match('/\A(?:0|[1-9][0-9]{0,4})\z/D',$length)||(int)$length>8192){throw new SecurityException('Request body exceeds its budget.','auth.request_denied');}if($method==='GET'&&(int)$length!==0){throw new \SoSecurity\Exception\ValidationException('Unexpected GET body.','auth.input');}
    $path=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_PATH') ?: '/managed-authentication.php';$uri=$_SERVER['REQUEST_URI']??'';if(!preg_match('/\A\/[A-Za-z0-9_\/.-]{1,255}\z/D',$path)||strpos($path,'..')!==false||strlen($uri)>2048||$uri!==$path.($api?'?'.$query:'')){throw new \SoSecurity\Exception\ValidationException('Unexpected raw route.','auth.input');}
    $form=$method==='POST'?managedForm((int)$length):[];$action=$form['action']??'';$apiAction=strpos($action,'api_')===0;
    $fields=['login'=>['username','password'],'mfa'=>['type','proof'],'logout'=>[],'api_issue'=>['name','scopes','ttl'],'api_all'=>[],'api_rotate'=>['id','generation'],'api_replace'=>['id','generation','name','scopes','ttl'],'api_revoke'=>['id'],'api_revoke_all'=>[]];
    if($business&&($action!=='rename'||array_diff(array_keys($form),['action','id','version','title']))){throw new \SoSecurity\Exception\ValidationException('Use the exact business action and fields.','auth.input');}
    if(!$business&&$method==='POST'&&(!isset($fields[$action])||array_diff(array_keys($form),array_merge(['action','_csrf'],$fields[$action])))){throw new \SoSecurity\Exception\ValidationException('Unexpected action or fields.','auth.input');}
    if(($apiAction||$business)&&strpos($_SERVER['HTTP_ACCEPT']??'','application/json')===false){managedResponse(406,['error'=>'auth.accept'],true);return;}
    $bootstrap=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_BOOTSTRAP');$real=is_string($bootstrap)?realpath($bootstrap):false;$web=realpath($_SERVER['DOCUMENT_ROOT']??__DIR__);
    if($real===false||$web===false||!is_file($real)||is_link($bootstrap)||($real===$web||strpos($real,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0)||((fileperms($real)&0077)!==0)){throw new \RuntimeException('Use a private bootstrap outside the web root.');}
    $directory=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_STATE');$state=is_string($directory)?realpath($directory):false;
    if($state===false||$web===$state||strpos($state,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0||!is_dir($state)||((fileperms($state)&0077)!==0)){throw new \RuntimeException('Use a private local request-budget directory.');}
    $http=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_HTTP')==='1';if($http&&!in_array($_SERVER['REMOTE_ADDR']??'',['127.0.0.1','::1'],true)){throw new \RuntimeException('Plain HTTP is restricted to local tests.');}if(!$http&&!in_array(strtolower((string)($_SERVER['HTTPS']??'')),['on','1'],true)){throw new \RuntimeException('Authenticated requests require HTTPS.');}
    $origin=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_ORIGIN');if($origin!==false){new \SoSecurity\Link\Policy($origin,300,86400,32,$http);if(($http?substr($origin,0,7)!=='http://':substr($origin,0,8)!=='https://')||($_SERVER['HTTP_HOST']??'')!==substr($origin,strpos($origin,'//')+2)){throw new \RuntimeException('Host and transport must match the fixed origin.');}}
    if($method==='POST'&&$origin!==false&&isset($_SERVER['HTTP_ORIGIN'])&&$_SERVER['HTTP_ORIGIN']!==$origin){throw new SecurityException('Request origin denied.','auth.request_denied');}
    $budget=new RateLimiter(new FileStore($state,'managed-auth-requests'),new Policy(40,60,[60],120));$apiBudget=new RateLimiter(new FileStore($state,'managed-api-requests'),new Policy(120,60,[60],240));$guarded=false;$apiGuarded=false;$binding='';$csrf=null;
    if(!$api){
        SessionSecurity::configure(!$http);session_name('SoSecurityManagedExample');if(!session_start()){throw new \RuntimeException('Cannot start the host session.');}$lifecycle=new SessionSecurity();if(!$lifecycle->touch()){unset($_SESSION['managed_subject'],$_SESSION['managed_token'],$_SESSION['managed_pending']);}if(!isset($_SESSION['managed_binding'])){$_SESSION['managed_binding']=bin2hex(random_bytes(32));}$binding=$_SESSION['managed_binding'];$csrf=new CsrfTokens(new SessionStore('managed-auth-controls'));
    }
    $requestGuard=static function()use($csrf,&$binding,$budget,$apiBudget,&$guarded,$form,$method,$api,$apiAction):bool{
        if($guarded){return true;}if($api||$method!=='POST'||!$csrf instanceof CsrfTokens||!$csrf->verify('controls',$binding,$form['_csrf']??null)){throw new SecurityException('Request protection failed.','auth.request_denied');}$limiter=$apiAction?$apiBudget:$budget;$decision=$limiter->consume($apiAction?'managed-api-controls':'managed-auth',$_SERVER['REMOTE_ADDR']??'unknown');if(!$decision->allowed){header('Retry-After: '.$decision->retryAfter);throw new SecurityException('Request budget exhausted.','auth.rate');}$guarded=true;return true;
    };
    // Host bootstraps wrap this preflight in StateRequests. current() must only observe $guarded.
    $requestCurrent=static function()use(&$guarded):bool{return $guarded;};
    $apiRequestGuard=static function(string $operation)use($api,&$apiGuarded,&$guarded):bool{return $operation==='authenticate'?$api&&$apiGuarded:!$api&&$guarded;};
    if($method==='POST'&&!$api){$requestGuard();} // Before any protected session verify/seen update.
    // Protected bundles may add the exact business_connection PDO after security and state_policy.
    $host=(static function(string $file,callable $requestGuard,callable $requestCurrent,callable $apiRequestGuard){return require $file;})($real,$requestGuard,$requestCurrent,$apiRequestGuard);$statePolicy=null;$businessConnection=null;if(is_array($host)){if(!in_array(array_keys($host),[['security','state_policy'],['security','state_policy','business_connection']],true)||!$host['state_policy'] instanceof \SoSecurity\Account\StateAccountPolicy||$origin===false){throw new \RuntimeException('Use an exact protected host bundle with a fixed origin.');}$security=$host['security'];$statePolicy=$host['state_policy'];$businessConnection=$host['business_connection']??null;if($businessConnection!==null&&!$businessConnection instanceof \PDO){throw new \RuntimeException('Use the exact optional business PDO.');}}else{$security=$host;}
    if(!$security instanceof Security||$security->config()->authentication()===null||!$security->config()->authentication()['managed_factors']||$security->config()->accountFactors()===null){throw new \RuntimeException('The private bootstrap must return managed authentication.');}
    if(($security->config()->authentication()['state_boundary']??null)!==null&&$origin===false){throw new \RuntimeException('Protected hosts require a fixed origin.');}
    $scope=$security->config()->accountFactors()['scope'];
    if($api){
        if($statePolicy===null){throw new \RuntimeException('Declare native protected API coverage.');}$decision=$apiBudget->consume('managed-api',$_SERVER['REMOTE_ADDR']??'unknown');if(!$decision->allowed){header('Retry-After: '.$decision->retryAfter);throw new SecurityException('Request budget exhausted.','auth.rate');}$apiGuarded=true;
        if($business){
            if(!$businessConnection instanceof \PDO){throw new \RuntimeException('Declare native business SQL coverage.');}require_once __DIR__.'/StateDocuments.php';
            $version=\SoSecurity\Account\Example\StateDocuments::rename($security->apiCredentials($statePolicy),$businessConnection,$scope,$_SERVER['HTTP_AUTHORIZATION']??null,$form['id']??'',managedInteger($form['version']??'',PHP_INT_MAX-1),$form['title']??'');
            if($version===null){header('WWW-Authenticate: Bearer');managedResponse(401,['error'=>'auth.denied'],true);return;}managedResponse(200,['document'=>['id'=>$form['id'],'version'=>$version]],true);return;
        }
        $proof=$security->apiCredentials($statePolicy)->fromAuthorization($scope,$_SERVER['HTTP_AUTHORIZATION']??null,'records:read');if($proof===null){header('WWW-Authenticate: Bearer');managedResponse(401,['error'=>'auth.denied'],true);return;}managedResponse(200,['identity'=>['subject'=>$proof->account()->subject()]],true);return;
    }
    if($apiAction){
        if($statePolicy===null||!isset($_SESSION['managed_subject'],$_SESSION['managed_token'])){throw new SecurityException('Current management session required.','auth.denied');}$registry=$security->apiCredentials($statePolicy);$subject=$_SESSION['managed_subject'];$token=$_SESSION['managed_token'];$ttl=isset($form['ttl'])?managedInteger($form['ttl'],31536000):null;$issued=null;$data=[];
        if($action==='api_issue'){$issued=$registry->issue($scope,$subject,$token,$form['name']??'',explode(',',$form['scopes']??''),$ttl);}
        elseif($action==='api_all'){$data=['credentials'=>array_map(static function($info):array{return $info->toArray();},$registry->all($scope,$subject,$token))];}
        elseif($action==='api_rotate'){$issued=$registry->rotate($scope,$subject,$token,$form['id']??'',managedInteger($form['generation']??'',PHP_INT_MAX));}
        elseif($action==='api_replace'){$issued=$registry->replace($scope,$subject,$token,$form['id']??'',managedInteger($form['generation']??'',PHP_INT_MAX),$form['name']??'',explode(',',$form['scopes']??''),$ttl);}
        elseif($action==='api_revoke'){$data=['revoked'=>$registry->revoke($scope,$subject,$token,$form['id']??'')];}
        else{$data=['revoked'=>$registry->revokeAll($scope,$subject,$token)];}
        if($issued!==null){$data=['issued_token'=>$issued->token(),'issued'=>$issued->metadata()->toArray()];}elseif(in_array($action,['api_rotate','api_replace'],true)){managedResponse(409,['error'=>'auth.conflict'],true);return;}managedResponse(200,$data+['csrf'=>$csrf->issue('controls',$binding)],true);return;
    }
    $sessions=$security->sessions();$flow=$security->authentication();$verified=isset($_SESSION['managed_subject'],$_SESSION['managed_token'])?$sessions->verify($scope,$_SESSION['managed_subject'],$_SESSION['managed_token']):null;if($verified===null){unset($_SESSION['managed_subject'],$_SESSION['managed_token']);}$status=200;$error=null;
    if($method==='POST'){
        if($action==='login'){
            if($verified!==null){$status=409;$error='auth.already_authenticated';}else{$result=$flow->password($scope,$binding,$form['username']??null,$form['password']??null,'Managed example');if($result->status()==='mfa_required'){$_SESSION['managed_pending']=$result->challenge();}elseif($result->status()==='authenticated'){$credential=$result->credential();$lifecycle->rotate();$csrf->revoke('controls',$binding);$binding=bin2hex(random_bytes(32));$_SESSION['managed_binding']=$binding;$_SESSION['managed_subject']=$result->account()->subject();$_SESSION['managed_token']=$credential->token();unset($_SESSION['managed_pending']);}else{$status=401;$error='auth.denied';}}
        }elseif($action==='mfa'){
            if(!isset($_SESSION['managed_pending'])){$status=401;$error='auth.denied';}else{$result=$flow->secondFactor($scope,$binding,$_SESSION['managed_pending'],['type'=>$form['type']??null,'code'=>$form['proof']??null]);if($result->status()==='authenticated'){$credential=$result->credential();$lifecycle->rotate();$csrf->revoke('controls',$binding);$binding=bin2hex(random_bytes(32));$_SESSION['managed_binding']=$binding;$_SESSION['managed_subject']=$result->account()->subject();$_SESSION['managed_token']=$credential->token();unset($_SESSION['managed_pending']);}else{$status=401;$error='auth.denied';}}
        }elseif($action==='logout'){
            if($verified!==null){$sessions->revoke($scope,$verified->account()->subject(),$verified->id());}$flow->cancel($scope,$binding);$csrf->revoke('controls',$binding);$lifecycle->rotate();$binding=bin2hex(random_bytes(32));$_SESSION['managed_binding']=$binding;unset($_SESSION['managed_subject'],$_SESSION['managed_token'],$_SESSION['managed_pending']);
        }
    }
    $verified=isset($_SESSION['managed_subject'],$_SESSION['managed_token'])?$sessions->verify($scope,$_SESSION['managed_subject'],$_SESSION['managed_token']):null;if($verified===null){unset($_SESSION['managed_subject'],$_SESSION['managed_token']);}$data=['stage'=>isset($_SESSION['managed_pending'])?'mfa_required':($verified===null?'anonymous':'authenticated'),'csrf'=>$csrf->issue('controls',$binding)];if($verified!==null){$data['session']=['id'=>$verified->id(),'strength'=>$verified->strength(),'method'=>$verified->method()];}if($error!==null){$data['error']=$error;}managedResponse($status,$data);
}catch(\SoSecurity\Exception\ValidationException $error){managedResponse(400,['error'=>'auth.input'],$api||$apiAction);}
catch(SecurityException $error){$reason=$error->reason();$denied=in_array($reason,['auth.request_denied','auth.denied','api_credentials.denied','api_credentials.reauthentication','api_credentials.scope_denied','authorization.denied','documents.conflict'],true);$status=$reason==='auth.rate'?429:($denied?403:503);managedResponse($status,['error'=>$reason==='auth.rate'?'auth.rate':($denied?'auth.denied':'auth.unavailable')],$api||$apiAction);}
catch(\Throwable $error){managedResponse(503,['error'=>'auth.unavailable'],$api||$apiAction);}
