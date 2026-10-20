<?php
declare(strict_types=1);
namespace SoSecurity\Examples\OperationHttp;
ini_set('display_errors','0');
$autoload=dirname(__DIR__).'/vendor/autoload.php';if(!is_file($autoload)){$autoload=dirname(__DIR__,3).'/autoload.php';}require $autoload;
require_once __DIR__.'/operation-work.php';
use PDO;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\LoginResult;
use SoSecurity\Auth\PasswordIdentityProvider;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\TotpSecondFactor;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Operation\Grants;
use SoSecurity\Operation\Policy;
use SoSecurity\Output\Escaper;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;

const SCOPE='operation-example';
function output(int $status,array $data): void
{
    http_response_code($status);header('Cache-Control: no-store');header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');
    if(session_status()===PHP_SESSION_ACTIVE){header('Set-Cookie: '.SessionSecurity::cookieHeader(getenv('SOSECURITY_OPERATION_EXAMPLE_HTTPS')!=='0'),false);}
    if(strpos($_SERVER['HTTP_ACCEPT'] ?? '','application/json')!==false){header('Content-Type: application/json; charset=utf-8');echo json_encode($data);return;}
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>高风险操作授权示例</title><style>body{font:16px/1.6 system-ui;max-width:42rem;margin:2rem auto;padding:0 1rem}form{display:flex;flex-wrap:wrap;gap:.75rem;margin:1rem 0}label{display:grid;max-width:100%}input,button,select{font:inherit;max-width:100%;box-sizing:border-box}button{padding:.3rem .6rem}pre{white-space:pre-wrap;overflow-wrap:anywhere}section{padding:1rem;border:1px solid #aaa}</style><main><h1>高风险操作授权示例</h1>';
    $review=$data['review'] ?? null;
    if($review!==null){echo '<section data-review><h2>请核对本次文档更新</h2><p>动作：document.update；文档：<code>'.Escaper::html($review['document_id']).'</code>；版本：'.Escaper::html($review['version']).'</p><p>新标题：<bdi>'.Escaper::html($review['title']).'</bdi></p><p>准备后需完成一次新的重新认证，再明确确认这组数据。</p></section>';}
    if(isset($data['csrf'])){
        $form='<form method="post"><input type="hidden" name="_csrf" value="'.Escaper::html($data['csrf']).'">';
        $context=$review===null ? '' : '<input type="hidden" name="review_id" value="'.Escaper::html($review['id']).'">';
        if($data['stage']==='mfa_required'){
            echo $form.$context.'<label>验证码或恢复码<input name="proof" maxlength="35" autocomplete="one-time-code"></label><label>方式<select name="type"><option value="totp">TOTP</option><option value="recovery">恢复码</option></select></label><button name="action" value="mfa">完成验证</button></form>';
        }else{
            echo $form.$context.'<label>账号<input name="username" maxlength="256" autocomplete="username"></label><label>密码<input type="password" name="password" maxlength="4096" autocomplete="current-password"></label><button name="action" value="'.($data['stage']==='authenticated'?'reauthenticate':'login').'">'.($data['stage']==='authenticated'?'为上述操作重新认证':'登录').'</button></form>';
        }
        if($data['stage']==='authenticated'){
            echo $form.'<label>文档编号<input name="document_id" value="a" maxlength="64"></label><label>拟修改的新标题<input name="title" maxlength="200"></label><button name="action" value="prepare">准备操作</button></form>';
            if($review!==null){echo $form.$context.'<button name="action" value="'.($review['phase']==='pending'?'confirm':'execute').'">'.($review['phase']==='pending'?'明确确认上述操作':'执行已确认的操作').'</button><button name="action" value="cancel">取消本次操作</button></form>';}
            echo $form.'<button name="action" value="logout">退出</button></form>';
        }
    }
    $display=$data;unset($display['csrf']);echo '<pre data-operation-state>'.Escaper::html(json_encode($display,JSON_PRETTY_PRINT)).'</pre></main></html>';
}
function privateDatabase(): PDO
{
    $path=getenv('SOSECURITY_OPERATION_EXAMPLE_DATABASE');$real=$path?realpath($path):false;$web=realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if($real===false || !is_file($real) || is_link($path) || (fileperms($real)&0077)!==0 || $web===false || $real===$web || strpos($real,rtrim($web,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)===0){throw new \RuntimeException('Configure an existing private database outside the web root.');}
    return new PDO('sqlite:'.$real,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
}
function record(PDO $pdo,string $scope,string $value,bool $username): ?PasswordRecord
{
    if($scope!==SCOPE){return null;}
    $query=$pdo->prepare('SELECT subject,password_hash,version,enabled,roles,mfa_required FROM operation_accounts WHERE tenant=:tenant AND '.($username?'username':'subject').'=:value');
    $query->execute(['tenant'=>SCOPE,'value'=>$value]);$row=$query->fetch(PDO::FETCH_ASSOC);if(!is_array($row)){return null;}
    if(!is_string($row['roles'])||strlen($row['roles'])>4096){throw new \RuntimeException('Invalid authoritative role data.');}
    $roles=json_decode($row['roles'],true,4);if(!is_array($roles) || !in_array((string)$row['enabled'],['0','1'],true) || !in_array((string)$row['mfa_required'],['0','1'],true)){throw new \RuntimeException('Invalid authoritative account.');}
    return new PasswordRecord(new Account(SCOPE,$row['subject'],$row['version'],(int)$row['enabled']===1,$roles,(int)$row['mfa_required']===1),$row['password_hash']);
}
try{
    $database=privateDatabase();$directory=getenv('SOSECURITY_OPERATION_EXAMPLE_STORAGE');$dummy=getenv('SOSECURITY_OPERATION_EXAMPLE_DUMMY_HASH');
    if(!$directory || !$dummy){throw new \RuntimeException('Configure private shared storage and a dummy hash.');}
    $store=new FileStore($directory,'operation-example');$ip=(new \SoSecurity\Http\ClientIp())->resolve($_SERVER);
    $entry=(new \SoSecurity\RateLimit\RateLimiter($store,new \SoSecurity\RateLimit\Policy(120,60,[10],120)))->consume('entry',$ip);
    if(!$entry->allowed){header('Retry-After: '.$entry->retryAfter);output(429,['error'=>'operation.rate']);return;}
    $secure=getenv('SOSECURITY_OPERATION_EXAMPLE_HTTPS')!=='0';SessionSecurity::configure($secure);session_name('SoSecurityOperationExample');
    ini_set('session.cookie_path',rtrim(str_replace('\\','/',dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/.').'/');
    if(!session_start()){throw new \RuntimeException('Cannot start protected host session.');}
    $csrf=new CsrfTokens(new SessionStore('operation-controls'));$lifecycle=new SessionSecurity();
    if(!isset($_SESSION['operation_binding'])){$_SESSION['operation_binding']=bin2hex(random_bytes(32));}$binding=$_SESSION['operation_binding'];$retry=0;
    $guard=function () use ($csrf,&$binding,$store,$ip,&$retry): bool {
        static $allowed=null;if($allowed!==null){return $allowed;}
        if(($_SERVER['REQUEST_METHOD'] ?? '')!=='POST' || !$csrf->verify('controls',$binding,$_POST['_csrf'] ?? null)){return $allowed=false;}
        $result=(new \SoSecurity\RateLimit\RateLimiter($store,new \SoSecurity\RateLimit\Policy(80,60,[10],120)))->consume('actions',$ip);$retry=$result->retryAfter;return $allowed=$result->allowed;
    };
    $provider=new PasswordIdentityProvider(function(string $scope,string $username)use($database){return record($database,$scope,$username,true);},function(string $scope,string $subject)use($database){return record($database,$scope,$subject,false);},new \SoSecurity\Password\PasswordHasher(),$dummy);
    $factor=null;$encoded=getenv('SOSECURITY_OPERATION_EXAMPLE_MFA_KEY');
    if($encoded!==false && $encoded!==''){$key=base64_decode($encoded,true);if(!is_string($key)||strlen($key)!==32){throw new \RuntimeException('Invalid MFA key.');}$factor=new TotpSecondFactor(new \SoSecurity\Mfa\TotpFactors($store,new \SoSecurity\Crypto\Cipher('current',['current'=>$key],'operation-example:mfa'),'Operation example'));}
    $sessions=new SessionRegistry($store,$provider,$factor,null,300,900,16);$flow=new AuthenticationFlow($store,$provider,$sessions,$guard,$factor);
    $policy=getenv('SOSECURITY_OPERATION_EXAMPLE_PASSWORD_PROFILE')==='1' ? new Policy(120,8,300,1,['password']) : new Policy();
    $authorizer=new Authorizer($provider,new RolePolicy(['document.update'=>['type'=>'document','roles'=>['editor'],'fields'=>['title'],'owner_attribute'=>'owner']]));
    $operations=new Grants($store,$sessions,$authorizer,$guard,$policy);
    $verified=isset($_SESSION['operation_subject'],$_SESSION['operation_session']) ? $sessions->verify(SCOPE,$_SESSION['operation_subject'],$_SESSION['operation_session']) : null;
    $accept=function(LoginResult $result)use($lifecycle,$sessions,$csrf,&$binding):void{
        if($result->status()==='mfa_required'){$_SESSION['operation_mfa']=$result->challenge();return;}
        if($result->status()!=='authenticated'){return;}$credential=$result->credential();$account=$result->account();
        try{$lifecycle->rotate();}catch(\Throwable $error){$sessions->revoke(SCOPE,$account->subject(),$credential->id());throw $error;}
        $csrf->revoke('controls',$binding);$binding=bin2hex(random_bytes(32));$_SESSION['operation_binding']=$binding;
        $_SESSION['operation_subject']=$account->subject();$_SESSION['operation_session']=$credential->token();unset($_SESSION['operation_mfa']);
    };
    $status=200;$extra=[];$method=$_SERVER['REQUEST_METHOD'] ?? 'GET';
    if($method==='POST'){
        if(!$guard()){$status=$retry>0?429:403;if($retry>0){header('Retry-After: '.$retry);}$extra=['error'=>$retry>0?'operation.rate':'operation.request_denied'];}
        else{
            try{
                $action=$_POST['action'] ?? null;$fields=['login'=>['username','password'],'reauthenticate'=>['username','password','review_id'],'mfa'=>['proof','type','review_id'],'prepare'=>['document_id','title'],'confirm'=>['review_id'],'execute'=>['review_id'],'cancel'=>['review_id'],'logout'=>[]];
                if(!is_string($action)||!isset($fields[$action])||array_diff(array_keys($_POST),array_merge(['action','_csrf'],$fields[$action]))){throw new ValidationException('Unexpected operation request fields.','operation.input');}
                $review=$_SESSION['operation_review'] ?? null;
                if(in_array($action,['confirm','execute','cancel'],true) || (in_array($action,['reauthenticate','mfa'],true)&&$review!==null)){
                    if(!is_array($review)||!is_string($_POST['review_id'] ?? null)||!hash_equals($review['workflow_id'],$_POST['review_id'])){throw new SecurityException('Displayed operation changed; refresh and review again.','operation.review_changed');}
                }
                if($action==='login'||$action==='reauthenticate'){
                    if(($action==='reauthenticate'&&$verified===null)||($action==='login'&&$verified!==null)){throw new SecurityException('Authentication stage mismatch.','operation.authentication');}
                    $result=$flow->password(SCOPE,$binding,$_POST['username'] ?? null,$_POST['password'] ?? null,'Operation browser',$action==='reauthenticate'?$_SESSION['operation_session']:null);$accept($result);
                    if(in_array($result->status(),['denied','enrollment_required'],true)){$status=401;$extra=['error'=>'operation.authentication'];}
                }elseif($action==='mfa'){
                    $result=$flow->secondFactor(SCOPE,$binding,$_SESSION['operation_mfa'] ?? null,['type'=>$_POST['type'] ?? null,'code'=>$_POST['proof'] ?? null]);$accept($result);if($result->status()==='denied'){$status=401;$extra=['error'=>'operation.authentication'];}
                }else{
                    if($verified===null){throw new SecurityException('Current authenticated session required.','operation.authentication');}$subject=$verified->account()->subject();$token=$_SESSION['operation_session'];
                    if($action==='prepare'){
                        if(!is_string($_POST['document_id'] ?? null)||!is_string($_POST['title'] ?? null)){throw new ValidationException('Invalid proposal.','operation.input');}
                        $intent=\SoSecurity\Examples\Operations\intent($database,SCOPE,$_POST['document_id'],$_POST['title']);
                        if(is_array($review)){$operations->revoke(SCOPE,$subject,$token,$review['workflow_id']);}unset($_SESSION['operation_review']);
                        $pending=$operations->begin(SCOPE,$subject,$token,$intent);$_SESSION['operation_review']=['workflow_id'=>$pending->id(),'subject'=>$subject,'session'=>$verified->id(),'document_id'=>$intent->resource()->id(),'version'=>$intent->resource()->version(),'title'=>$intent->parameters()['title'],'confirmation'=>$pending->token(),'grant'=>null,'phase'=>'pending','expires'=>$pending->expiresAt()];
                    }elseif($action==='confirm'){
                        if($review['phase']!=='pending'){throw new SecurityException('Operation confirmation already used.','operation.denied');}
                        $intent=\SoSecurity\Examples\Operations\intent($database,SCOPE,$review['document_id'],$review['title']);$grant=$operations->confirm(SCOPE,$subject,$token,$intent,$review['confirmation']);
                        if($grant===null){unset($_SESSION['operation_review']);throw new SecurityException('Operation confirmation not accepted.','operation.denied');}
                        $_SESSION['operation_review']['grant']=$grant->token();$_SESSION['operation_review']['confirmation']=null;$_SESSION['operation_review']['phase']='granted';$_SESSION['operation_review']['expires']=$grant->expiresAt();
                    }elseif($action==='execute'){
                        if($review['phase']!=='granted'){throw new SecurityException('Confirm before execution.','operation.denied');}
                        try{$intent=\SoSecurity\Examples\Operations\intent($database,SCOPE,$review['document_id'],$review['title']);$database->beginTransaction();$passwordRecord=record($database,SCOPE,$subject,false);if($passwordRecord===null){throw new SecurityException('Current account unavailable.','operation.authentication');}\SoSecurity\Examples\Operations\apply($database,$operations,SCOPE,$subject,$token,$intent,$review['grant'],$passwordRecord);$database->commit();$extra=['applied'=>true];}
                        catch(\Throwable $error){if($database->inTransaction()){$database->rollBack();}throw $error;}finally{unset($_SESSION['operation_review']);}
                    }elseif($action==='cancel'){$operations->revoke(SCOPE,$subject,$token,$review['workflow_id']);unset($_SESSION['operation_review']);}
                    elseif($action==='logout'){$sessions->revoke(SCOPE,$subject,$verified->id());$flow->cancel(SCOPE,$binding);$csrf->revoke('controls',$binding);$lifecycle->rotate();$binding=bin2hex(random_bytes(32));$_SESSION['operation_binding']=$binding;unset($_SESSION['operation_subject'],$_SESSION['operation_session'],$_SESSION['operation_mfa'],$_SESSION['operation_review']);}
                }
            }catch(ValidationException $error){$status=400;$extra=['error'=>$error->reason()];}
            catch(SecurityException $error){$reason=$error->reason();$status=in_array($reason,['operation.authentication','operation.denied','operation.review_changed','operation.request_denied','authorization.denied'],true)?403:(in_array($reason,['operation.conflict','operation.expired'],true)?409:503);$extra=['error'=>$reason];}
        }
    }elseif($method!=='GET'){header('Allow: GET, POST');$status=405;$extra=['error'=>'operation.method'];}
    $verified=isset($_SESSION['operation_subject'],$_SESSION['operation_session'])?$sessions->verify(SCOPE,$_SESSION['operation_subject'],$_SESSION['operation_session']):null;
    if($verified===null){unset($_SESSION['operation_subject'],$_SESSION['operation_session']);}
    $review=$_SESSION['operation_review'] ?? null;
    if($review!==null && ($verified===null||$review['subject']!==$verified->account()->subject()||$review['session']!==$verified->id()||$review['expires']<=time())){unset($_SESSION['operation_review']);$review=null;}
    $public=$review===null?null:['id'=>$review['workflow_id'],'phase'=>$review['phase'],'document_id'=>$review['document_id'],'version'=>$review['version'],'title'=>$review['title'],'expires_at'=>$review['expires']];
    output($status,$extra+['stage'=>isset($_SESSION['operation_mfa'])?'mfa_required':($verified===null?'anonymous':'authenticated'),'csrf'=>$csrf->issue('controls',$binding),'review'=>$public,'policy'=>['methods'=>$policy->methods(),'minimum_strength'=>$policy->minimumStrength()],
        'session'=>$verified===null?null:['id'=>$verified->id(),'method'=>$verified->method(),'strength'=>$verified->strength()]]);
}catch(\Throwable $error){if(isset($database)&&$database instanceof PDO&&$database->inTransaction()){$database->rollBack();}output(503,['error'=>'operation.unavailable']);}
