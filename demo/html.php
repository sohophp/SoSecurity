<?php
declare(strict_types=1);
namespace SoSecurityDemo;
use SoSecurity\Output\HtmlCleaner;
use SoSecurity\Output\HtmlPolicy;
use SoSecurity\Output\HtmlPurifierSanitizer;
use SoSecurity\Output\HtmlSanitizer;

final class HtmlSamples
{
    public static function dependency(): bool
    {
        // Fixed operator-installed optional dependency; never a URL/request-provided autoload path.
        $autoload=dirname(__DIR__).'/integrations/htmlpurifier/vendor/autoload.php';
        if (!class_exists('HTMLPurifier',false) && is_file($autoload)) { require_once $autoload; }
        return class_exists('HTMLPurifier') && defined('HTMLPurifier::VERSION') && HtmlPurifierSanitizer::supportsVersion(\HTMLPurifier::VERSION) && extension_loaded('dom') && extension_loaded('ctype');
    }
    public static function run(string $action,string $input): array
    {
        self::dependency();
        $options=['maximum_input'=>8192,'maximum_output'=>16384,'maximum_nodes'=>256,'maximum_depth'=>24,'maximum_attribute'=>1024,'allow_links'=>$action==='links'];
        $provider=new HtmlPurifierSanitizer($options['allow_links']);
        if ($action==='normal') { $input='<h2>测试标题</h2><p>中文<strong>粗体</strong>和<em>斜体</em></p><ul><li>第一项</li><li>第二项</li></ul>'; }
        if ($action==='attack') { $input='<p id="location" onclick="window.pwn=1">安全文字<script>window.pwn=1</script><img src="https://evil.invalid/test" onerror="window.pwn=1"><svg onload="window.pwn=1"></svg></p>'; }
        if ($action==='tree_limit') { $input=str_repeat('<div>',30).'x'.str_repeat('</div>',30); }
        if ($action==='size_limit') { $input=str_repeat('x',8193); }
        if ($action==='provider_failure') { $provider=new class implements HtmlSanitizer {public function sanitize(string $html): string{throw new \RuntimeException('Fixed private demo adapter fault.');}}; $input='<p>测试</p>'; }
        $cleaner=new HtmlCleaner($provider,new HtmlPolicy($options));
        $output=$cleaner->clean($input);
        $_SESSION['demo_html_last']=['input'=>$input,'output'=>$output,'preview'=>$action!=='links'];
        return ['input'=>$input,'output'=>$output,'changed'=>$input!==$output,'preview'=>$action!=='links',
            'message'=>$action==='links' ? '带链接结果仅显示源码，不作为可点击预览；清理器不请求这些地址。' : '基础排版结果可预览；脚本/样式/资源/身份属性不在允许列表。'];
    }
    public static function state(): array
    {
        return ['dependency_ready'=>self::dependency(),'last'=>$_SESSION['demo_html_last'] ?? null,'maximum_input'=>8192,'maximum_nodes'=>256,
            'note'=>'仅用于HTML正文片段；原始HTML不执行，链接版不做可点击预览。'];
    }
}
