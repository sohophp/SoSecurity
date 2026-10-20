<?php
declare(strict_types=1);
namespace SoSecurity\Examples\WebhookHttp;

ini_set('display_errors', '0');
$autoload = dirname(__DIR__).'/vendor/autoload.php';
if (!is_file($autoload)) { $autoload = dirname(__DIR__, 3).'/autoload.php'; }
require $autoload;
require_once __DIR__.'/webhook-business.php';

use PDO;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\AuthenticationFlow;
use SoSecurity\Auth\PasswordIdentityProvider;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Auth\VerifiedSession;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Output\Escaper;
use SoSecurity\Session\SessionSecurity;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\SessionStore;
use SoSecurity\Webhook\Endpoint;
use SoSecurity\Webhook\Message;
use SoSecurity\Webhook\Request;
use SoSecurity\Webhook\VerifiedWebhook;

const SCOPE = 'webhook-example';
const ACCOUNT = 'publisher-example';

function output(int $status, array $data, bool $json = false): void
{
    http_response_code($status);
    header('Cache-Control: no-store, private'); header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    if (session_status() === PHP_SESSION_ACTIVE) { header('Set-Cookie: '.SessionSecurity::cookieHeader(getenv('SOSECURITY_WEBHOOK_EXAMPLE_HTTPS') !== '0'), false); }
    if ($json || strpos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false) {
        header('Content-Type: application/json; charset=utf-8'); echo json_encode($data); return;
    }
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Webhook消息管理</title><style>body{font:16px/1.6 system-ui;max-width:48rem;margin:2rem auto;padding:0 1rem}form{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}label{display:grid;max-width:100%}input,button{font:inherit;max-width:100%;box-sizing:border-box}article{border:1px solid #ccc;border-radius:.4rem;padding:1rem;margin:1rem 0;overflow-wrap:anywhere}article h3{margin:0}dl{display:grid;grid-template-columns:auto 1fr;gap:.3rem 1rem}dd{margin:0}pre{white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer}</style><main><h1>Webhook消息管理</h1><p>'.(!empty($data['processing_enabled'])?'查看接收和处理状态；重新安排失败消息后，由独立工作进程处理。':'查看最近接收的消息元数据。业务处理结果由业务系统另行确认。').'</p>';
    if(isset($data['error'])){
        $messages=['webhook_example.denied'=>'当前请求未获授权，请重新登录并完成强认证。','webhook_example.input'=>'请求内容无效，请刷新页面后重试。','webhook_example.rate'=>'操作过于频繁，请稍后重试。','webhook_example.conflict'=>'消息内容与既有记录冲突，请核实后处理。'];
        echo '<p role="alert">'.Escaper::html($messages[$data['error']] ?? '服务暂不可用，请联系管理员核对处理记录和配置。').'</p>';
    }elseif($status===401){echo '<p role="alert">登录未成功，请检查凭据后重试。</p>';}
    if (isset($data['csrf'])) {
        $form = '<form method="post"><input type="hidden" name="_csrf" value="'.Escaper::html($data['csrf']).'">';
        if (($data['stage'] ?? '') === 'mfa_required') {
            echo $form.'<input type="hidden" name="flow_id" value="'.Escaper::html($data['flow_id']).'"><label>TOTP验证码<input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code"></label><button name="action" value="second_factor">完成强认证</button></form>';
        } elseif (($data['stage'] ?? '') === 'authenticated') {
            echo '<p>当前操作者：'.Escaper::html($data['operator']).'</p>'.$form.'<button name="action" value="logout">退出管理会话</button></form>';
        } else {
            echo $form.'<label>账号<input name="username" maxlength="256" autocomplete="username"></label><label>密码<input type="password" name="password" maxlength="4096" autocomplete="current-password"></label><button name="action" value="login">登录</button></form>';
        }
    }
    if(($data['stage'] ?? '')==='authenticated'){
        if(array_key_exists('retry_scheduled',$data)){echo '<p role="status">'.($data['retry_scheduled']?'已安排重试，等待工作进程处理。':'当前消息不能重新安排；请核对处理状态与重试次数。').'</p>';}
        echo '<h2>最近接收的消息</h2>';
        if(empty($data['receipts'])){echo '<p>暂无接收记录。</p>';}
        foreach($data['receipts'] ?? [] as $receipt){
            $processing=$receipt['processing'] ?? null;$state=$processing['status'] ?? '';
            $labels=['ready'=>'等待处理','leased'=>'处理中','retry'=>'等待重试','succeeded'=>'处理完成','dead'=>'处理失败'];
            $label=$labels[$state] ?? (!empty($data['processing_enabled'])?'尚无可查看的处理状态':'已接收');
            echo '<article><h3>'.Escaper::html($receipt['event_id']).'</h3><p data-processing-status="'.Escaper::html($state).'">'.Escaper::html($label).'</p><dl><dt>资源</dt><dd>'.Escaper::html($receipt['resource_id']).'</dd><dt>消息类型</dt><dd>'.Escaper::html($receipt['event_type']).'</dd></dl>';
            if(is_array($processing)){echo '<p>本轮尝试 '.Escaper::html((string)$processing['attempt']).' 次，累计 '.Escaper::html((string)$processing['total_attempts']).' 次；人工重试 '.Escaper::html((string)$processing['manual_retries']).' 次。</p>';}
            if($state==='dead'){echo $form.'<input type="hidden" name="receipt_id" value="'.Escaper::html($receipt['receipt_id']).'"><button name="action" value="retry">重新安排处理</button></form>';}
            echo '</article>';
        }
    }
    $display = $data; unset($display['csrf'], $display['flow_id']);
    echo '<details><summary>查看诊断元数据</summary><pre data-webhook-state>'.Escaper::html(json_encode($display, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)).'</pre></details></main></html>';
}

function privateFile(string $name, int $maximum = 0): string
{
    $path = getenv($name); $real = $path ? realpath($path) : false; $web = realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if ($real === false || !is_file($real) || is_link($path) || (fileperms($real) & 0077) !== 0 || $web === false || $real === $web || strpos($real, rtrim($web, '/').'/') === 0 || ($maximum > 0 && filesize($real) > $maximum)) {
        throw new \RuntimeException('Configure a private file outside the web root.');
    }
    return $real;
}

function keys(string $name): array
{
    $raw = file_get_contents(privateFile($name, 16384), false, null, 0, 16385);
    $data = is_string($raw) && strlen($raw) <= 16384 ? json_decode($raw, true, 4) : null;
    if (!is_array($data) || count($data) !== 2 || !is_string($data['current'] ?? null) || !is_array($data['keys'] ?? null) || count($data['keys']) < 1 || count($data['keys']) > 8 || !isset($data['keys'][$data['current']])) { throw new \RuntimeException('Invalid private key configuration.'); }
    $decoded = [];
    foreach ($data['keys'] as $id => $encoded) {
        if (!is_string($encoded) || !is_string($value = base64_decode($encoded, true)) || base64_encode($value) !== $encoded || strlen($value) !== 32) { throw new \RuntimeException('Expected a canonical 32-byte private key.'); }
        $decoded[$id] = $value;
    }
    return [$data['current'], $decoded];
}

function limit(FileStore $store, string $purpose, string $subject, int $maximum): void
{
    $decision = (new \SoSecurity\RateLimit\RateLimiter($store, new \SoSecurity\RateLimit\Policy($maximum, 60, [10], 120)))->consume($purpose, $subject);
    if (!$decision->allowed) { throw new SecurityException('Request budget exhausted.', 'webhook_example.rate'); }
}

function passwordRecord(PDO $pdo, string $scope, string $value, bool $username = false): ?PasswordRecord
{
    if ($scope !== SCOPE) { return null; }
    $query = $pdo->prepare('SELECT subject,password_hash,version,enabled,roles,mfa_required FROM webhook_accounts WHERE tenant=:tenant AND '.($username ? 'username' : 'subject').'=:value');
    $query->execute(['tenant' => SCOPE, 'value' => $value]); $row = $query->fetch(PDO::FETCH_ASSOC);
    if (!is_array($row)) { return null; }
    if (!is_string($row['roles']) || strlen($row['roles']) > 4096 || !in_array((string)$row['enabled'], ['0','1'], true) || !in_array((string)$row['mfa_required'], ['0','1'], true)) { throw new \RuntimeException('Invalid identity source.'); }
    $roles = json_decode($row['roles'], true, 4);
    if (!is_array($roles) || array_values($roles) !== $roles) { throw new \RuntimeException('Invalid role source.'); }
    return new PasswordRecord(new Account(SCOPE, $row['subject'], $row['version'], (int)$row['enabled'] === 1, $roles, (int)$row['mfa_required'] === 1), $row['password_hash']);
}

function operator(SessionRegistry $sessions, string $subject, string $token): VerifiedSession
{
    $proof = $sessions->verify(SCOPE, $subject, $token, 2);
    if ($proof === null || !$proof->recent(300, time(), 2) || !in_array('admin', $proof->account()->roles(), true)) { throw new SecurityException('Current strong administrator required.', 'webhook_example.denied'); }
    return $proof;
}

$receive = false;
try {
    $origin = getenv('SOSECURITY_WEBHOOK_EXAMPLE_ORIGIN'); $storage = getenv('SOSECURITY_WEBHOOK_EXAMPLE_STORAGE');
    $processingFlag=getenv('SOSECURITY_WEBHOOK_EXAMPLE_PROCESSING');if($processingFlag!==false&&!in_array($processingFlag,['0','1'],true)){throw new \RuntimeException('Explicit processing flag required.');}$processingEnabled=$processingFlag==='1';
    $secure = getenv('SOSECURITY_WEBHOOK_EXAMPLE_HTTPS') !== '0'; $path = getenv('SOSECURITY_WEBHOOK_EXAMPLE_PATH') ?: '/webhooks.php';
    if (!$origin || !$storage) { throw new \RuntimeException('Configure explicit origin and private state.'); }
    new \SoSecurity\Link\Policy($origin, 300, 86400, 32, !$secure);
    if (($secure && (!in_array(strtolower($_SERVER['HTTPS'] ?? ''), ['on','1'], true) || substr($origin, 0, 8) !== 'https://')) || (!$secure && substr($origin, 0, 7) !== 'http://') || ($_SERVER['HTTP_HOST'] ?? '') !== substr($origin, strpos($origin, '//') + 2)) { throw new \RuntimeException('Actual transport/Host must match configured origin.'); }
    $query = $_SERVER['QUERY_STRING'] ?? ''; $receive = $query === 'receive=1';
    $rawUri = $_SERVER['REQUEST_URI'] ?? '';
    if ($rawUri !== $path.($receive ? '?receive=1' : '') || (!$receive && $query !== '')) { throw new ValidationException('Unexpected raw route.', 'webhook_example.input'); }
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, $receive ? ['POST'] : ['GET','POST'], true)) { header('Allow: '.($receive ? 'POST' : 'GET, POST')); output(405, ['error'=>'webhook_example.method'], $receive); return; }
    if (isset($_SERVER['HTTP_TRANSFER_ENCODING']) || isset($_SERVER['TRANSFER_ENCODING']) || isset($_SERVER['HTTP_CONTENT_ENCODING'])) { throw new ValidationException('Unsupported request framing.', 'webhook_example.input'); }
    $length = $_SERVER['CONTENT_LENGTH'] ?? '0'; $maximum = $receive ? 65536 : 8192;
    if (!is_string($length) || !preg_match('/\A(?:0|[1-9][0-9]{0,5})\z/D', $length) || (int)$length > $maximum || ($method === 'GET' && $length !== '0')) { throw new ValidationException('Request body exceeds budget.', 'webhook_example.input'); }
    if ($method === 'POST' && strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0])) !== ($receive ? 'application/json' : 'application/x-www-form-urlencoded')) { throw new ValidationException('Unexpected content type.', 'webhook_example.input'); }
    $directory = realpath($storage); $web = realpath($_SERVER['DOCUMENT_ROOT'] ?? __DIR__);
    if ($directory === false || $directory !== rtrim($storage, '/') || $web === false || $directory === $web || strpos($directory, rtrim($web, '/').'/') === 0) { throw new \RuntimeException('Configure canonical private state outside the web root.'); }
    $store = new FileStore($directory, SCOPE); $ip = (new \SoSecurity\Http\ClientIp())->resolve($_SERVER);
    limit($store, 'entry-global', 'all', 1200); limit($store, 'entry-ip', $ip, 240);
    $database = new PDO('sqlite:'.privateFile('SOSECURITY_WEBHOOK_EXAMPLE_DATABASE'), null, null, [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT=>1]);
    // Deployment creates the private file/schema. Requests never initialize schema or alter durability settings.
    list($sealCurrent, $sealSecrets) = keys('SOSECURITY_WEBHOOK_EXAMPLE_SEAL_KEYS');
    $endpointNamespace = null;
    $security = \SoSecurity\Security::fromArray(['site'=>SCOPE, 'webhooks'=>['events'=>[
        'scope'=>SCOPE, 'account'=>ACCOUNT, 'url'=>$origin.$path.'?receive=1', 'protocol'=>'standard-hmac',
        'policy'=>['allow_http'=>!$secure], 'key_provider'=>'publisher_keys', 'request_guard'=>'receive_boundary',
        'inbox'=>['connection'=>'receive_db', 'integrity_keys'=>'seals', 'association_guard'=>'business_association'],
    ]]], [
        'publisher_keys'=>static function (Endpoint $endpoint) use ($sealSecrets) {
            list(, $secrets) = keys('SOSECURITY_WEBHOOK_EXAMPLE_PROVIDER_KEYS');
            foreach ($secrets as $secret) { foreach ($sealSecrets as $seal) { if (hash_equals($secret, $seal)) { throw new \RuntimeException('Separate provider and sealing keys.'); } } }
            return new \SoSecurity\Webhook\KeySet($endpoint, $secrets);
        },
        'receive_boundary'=>static function () use ($receive): bool { return $receive; },
        'receive_db'=>$database, 'seals'=>new \SoSecurity\Support\HmacKeys($sealCurrent, $sealSecrets),
        'business_association'=>static function (Endpoint $endpoint, Message $message) use ($database, &$endpointNamespace): bool {
            if(!\SoSecurity\Examples\WebhookBusiness\associated($database,$endpoint,$message)){return false;}
            // Bound receive backlog while allowing an existing signed event to be retried at capacity.
            $query = $database->prepare('SELECT COUNT(*) FROM (SELECT 1 FROM sosecurity_webhook_inbox WHERE endpoint_key=:endpoint LIMIT 1001)');
            $namespace = $endpointNamespace;
            $query->execute(['endpoint'=>$namespace]);
            $count = (int)$query->fetchColumn();
            if ($count > 1000) { throw new \RuntimeException('Receive capacity unavailable.'); }
            if ($count === 1000) {
                $query = $database->prepare('SELECT 1 FROM sosecurity_webhook_inbox WHERE endpoint_key=:endpoint AND event_key=:event');
                $query->execute(['endpoint'=>$namespace, 'event'=>hash('sha256', $message->id())]);
                if ($query->fetchColumn() === false) { throw new \RuntimeException('Receive capacity unavailable.'); }
            }
            return true;
        },
    ]);
    $inbox = $security->webhookInbox('events');
    $endpointNamespace = $inbox->endpointKey();
    if ($receive) {
        // Some SAPIs erase repeated headers before PHP. A trusted ingress must reject them first.
        // This is a server-owned request attribute, never HTTP_X_* or a client-supplied assertion.
        if (($_SERVER['SOSECURITY_WEBHOOK_HEADERS_VALIDATED'] ?? '') !== '1') { throw new \RuntimeException('Require a trusted duplicate-rejecting ingress.'); }
        // Public delivery has no Session/CSRF/Cookie authority. Preserve php://input byte-for-byte.
        $body = file_get_contents('php://input', false, null, 0, 65537);
        if (!is_string($body) || strlen($body) !== (int)$length) { throw new ValidationException('Invalid raw request body.', 'webhook_example.input'); }
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        if (!is_array($headers)) { throw new \RuntimeException('Raw headers unavailable.'); }
        $request = new Request($method, $origin.$rawUri, $body, $headers);
        $receipt = $inbox->accept($request, static function (VerifiedWebhook $proof) use ($store): ?Message {
            $message=\SoSecurity\Examples\WebhookBusiness\map($proof->body(),$proof->endpoint(),$proof->messageId());if($message===null){return null;}
            limit($store, 'verified-source', ACCOUNT, 120);
            return $message;
        });
        if ($receipt === null) { output(403, ['error'=>'webhook_example.denied'], true); return; }
        output(200, ['received'=>true, 'receipt_id'=>$receipt->id(), 'duplicate'=>$receipt->duplicate()], true); return;
    }

    // Operator access uses current local identities and a real second factor, independent of publisher keys.
    $dummy = getenv('SOSECURITY_WEBHOOK_EXAMPLE_DUMMY_HASH');
    if (!$dummy) { throw new \RuntimeException('Configure the identity source.'); }
    $provider = new PasswordIdentityProvider(static function (string $scope, string $value) use ($database) { return passwordRecord($database, $scope, $value, true); }, static function (string $scope, string $value) use ($database) { return passwordRecord($database, $scope, $value); }, new \SoSecurity\Password\PasswordHasher(), $dummy);
    list($mfaCurrent, $mfaSecrets) = keys('SOSECURITY_WEBHOOK_EXAMPLE_MFA_KEYS');
    $factor = new \SoSecurity\Auth\TotpSecondFactor(new \SoSecurity\Mfa\TotpFactors($store, new \SoSecurity\Crypto\Cipher($mfaCurrent, $mfaSecrets, SCOPE.':mfa'), 'Webhook example'));
    $sessions = new SessionRegistry($store, $provider, $factor);
    SessionSecurity::configure($secure); session_name('SoSecurityWebhookExample'); ini_set('session.cookie_path', rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/.').'/');
    if (!session_start()) { throw new \RuntimeException('Cannot start protected management session.'); }
    if (!isset($_SESSION['webhook_binding'])) { $_SESSION['webhook_binding'] = bin2hex(random_bytes(32)); }
    $binding = $_SESSION['webhook_binding']; $csrf = new CsrfTokens(new SessionStore('webhook-controls'));
    $subject = $_SESSION['webhook_subject'] ?? null; $token = $_SESSION['webhook_session'] ?? null; $verified = null;
    if (is_string($subject) && is_string($token)) { $verified = $sessions->verify(SCOPE, $subject, $token); }
    if ($verified === null) { unset($_SESSION['webhook_subject'], $_SESSION['webhook_session']); }
    $protected = $method === 'POST' && $csrf->verify('controls', $binding, $_POST['_csrf'] ?? null);
    $flow = new AuthenticationFlow($store, $provider, $sessions, static function () use ($protected): bool { return $protected; }, $factor);
    $processor=null;$retried=null;
    if($processingEnabled){
        $processingSecurity=\SoSecurity\Security::fromArray(['site'=>SCOPE,'webhooks'=>['events'=>[
            'scope'=>SCOPE,'account'=>ACCOUNT,'url'=>$origin.$path.'?receive=1','protocol'=>'standard-hmac','policy'=>['allow_http'=>!$secure],
            'processing'=>['connection'=>'business_db','integrity_keys'=>'receipt_keys','mapper'=>'received_mapper','association_guard'=>'current_business','worker_guard'=>'status_operator','management_guard'=>'retry_operator'],
        ]]],['business_db'=>$database,'receipt_keys'=>new \SoSecurity\Support\HmacKeys($sealCurrent,$sealSecrets),
            'received_mapper'=>static function(string $body,Endpoint $endpoint,string $receipt,array $metadata):?Message{return \SoSecurity\Examples\WebhookBusiness\map($body,$endpoint,$metadata['message_id']);},
            'current_business'=>static function(Endpoint $endpoint,Message $message)use($database):bool{return \SoSecurity\Examples\WebhookBusiness\associated($database,$endpoint,$message);},
            'status_operator'=>static function(string $operation,Endpoint $endpoint,string $receipt,string $label)use($sessions,&$subject,&$token):bool{
                if($operation!=='status'||$label!=='operator'||!is_string($subject)||!is_string($token)){return false;}operator($sessions,$subject,$token);return true;
            },
            'retry_operator'=>static function(string $operation,Endpoint $endpoint,string $receipt,string $label)use($sessions,&$subject,&$token,$protected,$method):bool{
                if(!$protected||$method!=='POST'||($_POST['action'] ?? null)!=='retry'||$operation!=='retry'||$label!=='operator'||!is_string($subject)||!is_string($token)){return false;}operator($sessions,$subject,$token);return true;
            },
        ]);$processor=$processingSecurity->webhookProcessor('events');
    }
    $status = 200;
    if ($method === 'POST') {
        if (!$protected) { throw new SecurityException('Request protection failed.', 'webhook_example.denied'); }
        limit($store, 'operator-action', $ip, 60); $action = $_POST['action'] ?? null;
        $fields = ['login'=>['username','password'], 'second_factor'=>['flow_id','code'], 'logout'=>[]];if($processingEnabled){$fields['retry']=['receipt_id'];}
        if (!is_string($action) || !isset($fields[$action]) || array_diff(array_keys($_POST), array_merge(['action','_csrf'], $fields[$action]))) { throw new ValidationException('Unexpected management fields.', 'webhook_example.input'); }
        if($action==='retry'){
            if($verified===null){throw new SecurityException('Current operator required.','webhook_example.denied');}operator($sessions,$subject,$token);
            $receipt=$_POST['receipt_id'] ?? null;if(!is_string($receipt)||!preg_match('/\A[a-f0-9]{32}\z/D',$receipt)){throw new ValidationException('Invalid receipt.','webhook_example.input');}
            $result=$processor->retry($receipt,'operator');$retried=$result!==null;if(!$retried){$status=409;}
        } elseif ($action === 'logout') {
            if ($verified === null) { throw new SecurityException('Current session required.', 'webhook_example.denied'); }
            $sessions->revoke(SCOPE, $subject, $verified->id()); $flow->cancel(SCOPE, $binding); $csrf->revoke('controls', $binding); (new SessionSecurity())->rotate();
            $binding = bin2hex(random_bytes(32)); $_SESSION['webhook_binding'] = $binding; unset($_SESSION['webhook_subject'], $_SESSION['webhook_session'], $_SESSION['webhook_pending']); $verified = null;
        } else {
            if ($verified !== null) { throw new SecurityException('Already authenticated.', 'webhook_example.denied'); }
            if ($action === 'login') { $login = $flow->password(SCOPE, $binding, $_POST['username'] ?? null, $_POST['password'] ?? null); unset($_SESSION['webhook_pending']); }
            else {
                $pending = $_SESSION['webhook_pending'] ?? null;
                if (!is_string($pending) || !is_string($_POST['flow_id'] ?? null) || !hash_equals(hash('sha256', $pending), $_POST['flow_id'])) { throw new SecurityException('Pending login changed.', 'webhook_example.denied'); }
                $login = $flow->secondFactor(SCOPE, $binding, $pending, ['type'=>'totp', 'code'=>$_POST['code'] ?? null]);
            }
            if ($login->status() === 'mfa_required') { $_SESSION['webhook_pending'] = $login->challenge(); }
            elseif ($login->status() === 'authenticated') {
                $credential = $login->credential();
                try { (new SessionSecurity())->rotate(); } catch (\Throwable $error) { $sessions->revoke(SCOPE, $login->account()->subject(), $credential->id()); throw $error; }
                $csrf->revoke('controls', $binding); $binding = bin2hex(random_bytes(32)); $_SESSION['webhook_binding'] = $binding;
                $subject = $login->account()->subject(); $token = $credential->token(); $_SESSION['webhook_subject'] = $subject; $_SESSION['webhook_session'] = $token; unset($_SESSION['webhook_pending']); $verified = $sessions->verify(SCOPE, $subject, $token);
            } else { $status = 401; }
        }
    }
    $pending = $_SESSION['webhook_pending'] ?? null;
    $data = ['stage'=>$verified !== null ? 'authenticated' : (is_string($pending) ? 'mfa_required' : 'anonymous'), 'csrf'=>$csrf->issue('controls', $binding)];
    if($processingEnabled){$data['processing_enabled']=true;}
    if (is_string($pending)) { $data['flow_id'] = hash('sha256', $pending); }
    if ($verified !== null) {
        $before = operator($sessions, $subject, $token);
        // Read only inert, bounded metadata after current authorization; never return stored payloads or seals.
        $query = $database->prepare('SELECT receipt_id,event_id,event_type,resource_id,created_at FROM sosecurity_webhook_inbox WHERE endpoint_key=:endpoint AND length(CAST(receipt_id AS BLOB))=32 AND length(CAST(event_id AS BLOB))<=256 AND length(CAST(event_type AS BLOB))<=64 AND length(CAST(resource_id AS BLOB))<=256 ORDER BY created_at DESC,event_key LIMIT 20');
        $query->execute(['endpoint'=>$inbox->endpointKey()]); $rows = $query->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            if (!is_string($row['receipt_id']) || !preg_match('/\A[a-f0-9]{32}\z/D', $row['receipt_id']) || !is_string($row['event_id']) || !preg_match('/\A[!-~]{1,256}\z/D', $row['event_id']) || !is_string($row['event_type']) || !preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D', $row['event_type']) || !is_string($row['resource_id']) || !preg_match('//u', $row['resource_id']) || !preg_match('/\A[0-9]{1,18}\z/D', (string)$row['created_at'])) { throw new \RuntimeException('Invalid receive metadata.'); }
        }
        if($processor!==null){foreach($rows as &$row){$state=$processor->status($row['receipt_id'],'operator');$row['processing']=$state===null?null:$state->toArray();}unset($row);}
        $after = operator($sessions, $subject, $token);
        if (!hash_equals($before->account()->fingerprint(), $after->account()->fingerprint())) { throw new SecurityException('Operator changed during read.', 'webhook_example.denied'); }
        $data += ['operator'=>$subject, 'receipts'=>$rows];
        if($retried!==null){$data['retry_scheduled']=$retried;}
    }
    output($status, $data);
} catch (ValidationException $error) { output(400, ['error'=>'webhook_example.input'], $receive); }
catch (SecurityException $error) {
    $reason = $error->reason(); $status = $reason === 'webhook_example.rate' ? 429 : ($reason === 'webhook.inbox_conflict' ? 409 : ($reason === 'webhook_example.denied' ? 403 : 503));
    if ($status === 429) { header('Retry-After: 60'); }
    output($status, ['error'=>$status === 429 ? 'webhook_example.rate' : ($status === 409 ? 'webhook_example.conflict' : ($status === 403 ? 'webhook_example.denied' : 'webhook_example.unavailable'))], $receive);
} catch (\Throwable $error) { output(503, ['error'=>'webhook_example.unavailable'], $receive); }
