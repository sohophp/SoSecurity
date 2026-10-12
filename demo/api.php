<?php
declare(strict_types=1);
namespace SoSecurityDemo;
use SoSecurity\Api\ApiKeys;
use SoSecurity\Api\SigningKey;
use SoSecurity\Api\KeyRing;
use SoSecurity\Api\NonceStore;
use SoSecurity\Api\SignaturePolicy;
use SoSecurity\Api\HmacSigner;
use SoSecurity\Api\HmacVerifier;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;

/** Visitor-bound, short-lived test credentials. No real account or externally callable signed business endpoint. */
final class ApiSamples
{
    private $store;
    private $binding;
    private const TARGET='https://api.example.com/demo/task?item=1';
    private const BODY='{"demo":true}';
    public function __construct(AtomicStore $store,string $binding) { $this->store=$store; $this->binding=$binding; }
    private function key(): SigningKey
    {
        if (!isset($_SESSION['demo_signing_key'])) {
            $_SESSION['demo_signing_key']=['id'=>bin2hex(random_bytes(16)),'secret'=>random_bytes(32)];
        }
        $key=$_SESSION['demo_signing_key'];
        return new SigningKey($key['id'],$key['secret'],$this->binding,['demo:read']);
    }
    public function run(string $action,string $token=''): array
    {
        $keys=new ApiKeys($this->store);
        if ($action==='issue_key' || $action==='rotate_key' || $action==='revoke_key') {
            $id=$_SESSION['demo_api_key_id'] ?? null;
            if ($action==='revoke_key') {
                if ($id!==null) { $keys->revoke($id); }
                unset($_SESSION['demo_api_key_id']); return ['valid'=>true,'message'=>'当前测试凭据已撤销。'];
            }
            if ($action==='rotate_key') { $credential=$id===null ? null : $keys->rotate($id); }
            else {
                if ($id!==null) { $keys->revoke($id); }
                $credential=$keys->issue($this->binding,['demo:read'],120);
            }
            if ($credential===null) { return ['valid'=>false,'message'=>'请先签发测试凭据，或凭据已过期。']; }
            $_SESSION['demo_api_key_id']=$credential->identity()->id();
            return ['valid'=>true,'token'=>$credential->token(),'expires_at'=>$credential->expiresAt(),'message'=>'仅用于此访客的测试凭据；只在本次结果显示。轮换后旧凭据立即失效。'];
        }
        if ($action==='check_key' || $action==='scope_key') {
            $identity=$keys->fromAuthorization('Bearer '.$token,$action==='scope_key' ? 'demo:write' : 'demo:read');
            // Authentication alone does not grant access to another visitor's state.
            $valid=$identity!==null && hash_equals($this->binding,$identity->subject());
            return ['valid'=>$valid,'message'=>$valid ? '测试凭据和访客归属检查通过。' : '凭据、权限范围或访客归属未通过。'];
        }
        $key=$this->key(); $policy=new SignaturePolicy(['origin'=>'https://api.example.com','clock_skew'=>0]);
        $signer=new HmacSigner($policy,$key);
        if ($action==='sign') {
            $_SESSION['demo_signature']=$signer->sign('POST',self::TARGET,self::BODY,'application/json',60);
            return ['valid'=>true,'headers'=>$_SESSION['demo_signature'],'message'=>'服务器内部签名测试；目标为固定示例 URI，不发起网络请求，也不显示 HMAC 密钥。'];
        }
        $headers=$_SESSION['demo_signature'] ?? null;
        if ($headers===null) { return ['valid'=>false,'message'=>'请先生成签名。']; }
        $store=$this->store;
        if ($action==='store_failure') {
            $store=new class implements AtomicStore { public function transact(string $key,callable $callback) { throw new StorageException('Fixed demo fault.','storage.unavailable'); } };
        }
        if ($action==='expire') {
            $clock=new class implements Clock { public function now(): int { return time()-120; } };
            $headers=(new HmacSigner($policy,$key,$clock))->sign('POST',self::TARGET,self::BODY,'application/json',60);
        }
        $verifier=new HmacVerifier($policy,new KeyRing([$key]),new NonceStore($store));
        $valid=$verifier->verify('POST',self::TARGET,$action==='tamper' ? self::BODY.' ' : self::BODY,$headers,'demo:read')!==null;
        return ['valid'=>$valid,'message'=>$valid ? '签名通过，Nonce 已原子登记；重复验证会被拒绝。' : '篡改、过期或已使用的签名被拒绝。'];
    }
    public function state(): array
    {
        return ['key_id'=>$_SESSION['demo_api_key_id'] ?? null,'signature'=>$_SESSION['demo_signature'] ?? null,
            'target'=>self::TARGET,'body'=>self::BODY,'limits'=>'Bearer 测试凭据 120 秒；签名 60 秒，时间偏差 0 秒；服务端使用共享文件存储。'];
    }
}
