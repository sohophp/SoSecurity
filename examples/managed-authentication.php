<?php
declare(strict_types=1);

// The private bootstrap returns one Security built from the host's current account PDO.
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

function managedResponse(int $status,array $data):void
{
    http_response_code($status);
    header('Cache-Control: no-store');header('Pragma: no-cache');
    header('Referrer-Policy: no-referrer');header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    if(session_status()===PHP_SESSION_ACTIVE){header('Set-Cookie: '.SessionSecurity::cookieHeader(getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_HTTP')!=='1'),false);}
    if(strpos($_SERVER['HTTP_ACCEPT']??'','text/html')===false){header('Content-Type: application/json; charset=utf-8');echo json_encode($data);return;}
    header('Content-Type: text/html; charset=utf-8');
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

try{
    $bootstrap=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_BOOTSTRAP');$real=is_string($bootstrap)?realpath($bootstrap):false;
    $web=realpath($_SERVER['DOCUMENT_ROOT']??__DIR__);
    if($real===false||$web===false||!is_file($real)||is_link($bootstrap)||($real===$web||strpos($real,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0)||((fileperms($real)&0077)!==0)){
        throw new \RuntimeException('Use a private bootstrap outside the web root.');
    }
    $directory=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_STATE');$state=is_string($directory)?realpath($directory):false;
    if($state===false||$web===$state||strpos($state,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0||!is_dir($state)||((fileperms($state)&0077)!==0)){
        throw new \RuntimeException('Use a private local request-budget directory.');
    }
    $http=getenv('SOSECURITY_MANAGED_AUTH_EXAMPLE_HTTP')==='1';
    if($http&&!in_array($_SERVER['REMOTE_ADDR']??'',['127.0.0.1','::1'],true)){throw new \RuntimeException('Plain HTTP is restricted to local tests.');}
    if(!$http&&!in_array(strtolower((string)($_SERVER['HTTPS']??'')),['on','1'],true)){throw new \RuntimeException('Authenticated requests require HTTPS.');}
    SessionSecurity::configure(!$http);session_name('SoSecurityManagedExample');
    if(!session_start()){throw new \RuntimeException('Cannot start the host session.');}
    $lifecycle=new SessionSecurity();if(!$lifecycle->touch()){unset($_SESSION['managed_subject'],$_SESSION['managed_token'],$_SESSION['managed_pending']);}
    if(!isset($_SESSION['managed_binding'])){$_SESSION['managed_binding']=bin2hex(random_bytes(32));}
    $binding=$_SESSION['managed_binding'];$csrf=new CsrfTokens(new SessionStore('managed-auth-controls'));
    $budget=new RateLimiter(new FileStore($state,'managed-auth-requests'),new Policy(40,60,[60],120));$guarded=false;
    $requestGuard=static function()use($csrf,&$binding,$budget,&$guarded):bool{
        if($guarded){return true;}
        $length=$_SERVER['CONTENT_LENGTH']??'0';
        if(($_SERVER['REQUEST_METHOD']??'')!=='POST'||!is_string($length)||!preg_match('/\A[0-9]{1,5}\z/D',$length)||(int)$length>8192||!$csrf->verify('controls',$binding,$_POST['_csrf']??null)){
            throw new SecurityException('Request protection failed.','auth.request_denied');
        }
        $decision=$budget->consume('managed-auth',$_SERVER['REMOTE_ADDR']??'unknown');
        if(!$decision->allowed){header('Retry-After: '.$decision->retryAfter);throw new SecurityException('Request budget exhausted.','auth.rate');}
        $guarded=true;return true;
    };
    // Included in this function scope so the trusted host can inject $requestGuard.
    $security=require $real;
    if(!$security instanceof Security||$security->config()->authentication()===null||!$security->config()->authentication()['managed_factors']||$security->config()->accountFactors()===null){
        throw new \RuntimeException('The private bootstrap must return managed authentication.');
    }
    $scope=$security->config()->accountFactors()['scope'];$sessions=$security->sessions();$flow=$security->authentication();
    $verified=isset($_SESSION['managed_subject'],$_SESSION['managed_token'])?$sessions->verify($scope,$_SESSION['managed_subject'],$_SESSION['managed_token']):null;
    if($verified===null){unset($_SESSION['managed_subject'],$_SESSION['managed_token']);}
    $method=$_SERVER['REQUEST_METHOD']??'GET';$status=200;$error=null;
    if($method==='POST'){
        $requestGuard();$action=$_POST['action']??null;
        if($action==='login'){
            if($verified!==null){$status=409;$error='auth.already_authenticated';}
            else{
                $result=$flow->password($scope,$binding,$_POST['username']??null,$_POST['password']??null,'Managed example');
                if($result->status()==='mfa_required'){$_SESSION['managed_pending']=$result->challenge();}
                elseif($result->status()==='authenticated'){$credential=$result->credential();$lifecycle->rotate();$csrf->revoke('controls',$binding);$binding=bin2hex(random_bytes(32));$_SESSION['managed_binding']=$binding;$_SESSION['managed_subject']=$result->account()->subject();$_SESSION['managed_token']=$credential->token();unset($_SESSION['managed_pending']);}
                else{$status=401;$error='auth.denied';}
            }
        }elseif($action==='mfa'){
            if(!isset($_SESSION['managed_pending'])){$status=401;$error='auth.denied';}
            else{
                $result=$flow->secondFactor($scope,$binding,$_SESSION['managed_pending'],['type'=>$_POST['type']??null,'code'=>$_POST['proof']??null]);
                if($result->status()==='authenticated'){$credential=$result->credential();$lifecycle->rotate();$csrf->revoke('controls',$binding);$binding=bin2hex(random_bytes(32));$_SESSION['managed_binding']=$binding;$_SESSION['managed_subject']=$result->account()->subject();$_SESSION['managed_token']=$credential->token();unset($_SESSION['managed_pending']);}
                else{$status=401;$error='auth.denied';}
            }
        }elseif($action==='logout'){
            if($verified!==null){$sessions->revoke($scope,$verified->account()->subject(),$verified->id());}
            $flow->cancel($scope,$binding);$csrf->revoke('controls',$binding);$lifecycle->rotate();$binding=bin2hex(random_bytes(32));$_SESSION['managed_binding']=$binding;unset($_SESSION['managed_subject'],$_SESSION['managed_token'],$_SESSION['managed_pending']);
        }else{$status=400;$error='auth.input';}
    }elseif($method!=='GET'){header('Allow: GET, POST');$status=405;$error='auth.method';}
    $verified=isset($_SESSION['managed_subject'],$_SESSION['managed_token'])?$sessions->verify($scope,$_SESSION['managed_subject'],$_SESSION['managed_token']):null;
    if($verified===null){unset($_SESSION['managed_subject'],$_SESSION['managed_token']);}
    $data=['stage'=>isset($_SESSION['managed_pending'])?'mfa_required':($verified===null?'anonymous':'authenticated'),'csrf'=>$csrf->issue('controls',$binding)];
    if($verified!==null){$data['session']=['id'=>$verified->id(),'strength'=>$verified->strength(),'method'=>$verified->method()];}
    if($error!==null){$data['error']=$error;}
    managedResponse($status,$data);
}catch(SecurityException $error){managedResponse($error->reason()==='auth.request_denied'?403:($error->reason()==='auth.rate'?429:503),['error'=>$error->reason()]);}
catch(\Throwable $error){managedResponse(503,['error'=>'auth.unavailable']);}
