<?php
declare(strict_types=1);
namespace SoSecurityDemo;
use SoSecurity\Csrf\SignedTokens;
use SoSecurity\Csrf\RequestPolicy;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Http\Cookie;

/** Session owns only UI/authentication test context; SignedTokens does not use it or any token store. */
final class SignedCsrfSamples
{
    private $binding; private $path; private $secure;
    public function __construct(string $binding,string $path,bool $secure) { $this->binding=$binding; $this->path=$path; $this->secure=$secure; }
    private function binding(): string { return $this->binding.':'.($_SESSION['demo_signed_epoch'] ?? 1); }
    private function tokens(): SignedTokens
    {
        if (!isset($_SESSION['demo_signed_keys'])) { $_SESSION['demo_signed_keys']=['k1'=>random_bytes(32)]; $_SESSION['demo_signed_current']='k1'; $_SESSION['demo_signed_number']=1; }
        return new SignedTokens(new HmacKeys($_SESSION['demo_signed_current'],$_SESSION['demo_signed_keys']),'demo-signed-csrf',30,new DemoClock('signed-csrf'));
    }
    public function run(string $action,string $submitted,string $method,string $path): array
    {
        $tokens=$this->tokens();
        if ($action==='bad_key') { new HmacKeys('bad',['bad'=>'too-short']); }
        if ($action==='policy') {
            $required=(new RequestPolicy([['method'=>'POST','path'=>'/hooks/demo']]))->requiresToken($method,$path);
            return ['requires_token'=>$required,'message'=>'仅解释固定示例策略；豁免不等于认证成功或允许业务执行。'];
        }
        if ($action==='issue') {
            $token=$tokens->reuseOrIssue('playground',$this->binding(),$_COOKIE['SoSecuritySignedCsrfDemo'] ?? null);
            $_SESSION['demo_signed_token']=$token;
            header('Set-Cookie: '.Cookie::header('SoSecuritySignedCsrfDemo',$token,$this->path,$this->secure,true,'Lax',30),false);
            return ['valid'=>true,'message'=>'已签发或复用30秒有效令牌；实际双重提交用独立演示Cookie。'];
        }
        if ($action==='expire') { (new DemoClock('signed-csrf'))->advance(31); return ['valid'=>true,'message'=>'仅推进本访客的演示时钟；原令牌现在过期。']; }
        if ($action==='binding_change') {
            $_SESSION['demo_signed_epoch']=($_SESSION['demo_signed_epoch'] ?? 1)+1;
            return ['valid'=>true,'message'=>'已模拟新的登录绑定；旧令牌失效，不改变真实业务登录。'];
        }
        if ($action==='rotate_keep' || $action==='rotate_drop') {
            $old=$_SESSION['demo_signed_current']; $next='k'.(++$_SESSION['demo_signed_number']);
            $_SESSION['demo_signed_keys']=$action==='rotate_keep' ? [$old=>$_SESSION['demo_signed_keys'][$old],$next=>random_bytes(32)] : [$next=>random_bytes(32)];
            $_SESSION['demo_signed_current']=$next;
            return ['valid'=>true,'message'=>$action==='rotate_keep' ? '新签发使用新密钥，保留上一把密钥验证旧令牌。' : '已移除旧密钥，旧令牌立即拒绝。'];
        }
        if ($action==='tamper' && $submitted!=='') { $submitted[strlen($submitted)-1]=$submitted[strlen($submitted)-1]==='a' ? 'b' : 'a'; }
        if ($action==='double' || $action==='cookie_mismatch') {
            $cookie=$action==='cookie_mismatch' ? $tokens->issue('playground','other-binding') : ($_COOKIE['SoSecuritySignedCsrfDemo'] ?? null);
            $valid=$tokens->verifyDoubleSubmit('playground',$this->binding(),$cookie,$submitted);
        } else { $valid=$tokens->verify($action==='cross_scope' ? 'other' : 'playground',$action==='cross_binding' ? 'other-binding' : $this->binding(),$submitted); }
        return ['valid'=>$valid,'message'=>$valid ? '签名与绑定验证通过；纯无状态令牌允许有效期内重用，不保证单次消费。' : '令牌、范围、登录绑定、Cookie匹配或期限未通过。'];
    }
    public function state(): array
    {
        return ['token'=>$_SESSION['demo_signed_token'] ?? null,'current_key'=>$_SESSION['demo_signed_current'] ?? null,
            'ttl_seconds'=>30,'single_use'=>false,'note'=>'演示Session保存控件显示和模拟身份；核心不存储令牌，不显示秘密。'];
    }
}
