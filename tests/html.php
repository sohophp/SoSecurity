<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/integrations/htmlpurifier/vendor/autoload.php';
use SoSecurity\Output\HtmlCleaner;
use SoSecurity\Output\HtmlPolicy;
use SoSecurity\Output\HtmlPurifierSanitizer;
use SoSecurity\Output\HtmlSanitizer;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
$cleaner=new HtmlCleaner(new HtmlPurifierSanitizer());
Check::same('<p>中文<strong>粗体</strong><em>斜体</em></p>',$cleaner->clean('<p>中文<strong>粗体</strong><em>斜体</em></p>'));
Check::same('',$cleaner->clean(''));
Check::same('<ul><li>one</li><li>two</li></ul>',$cleaner->clean('<ul><li>one<li>two</ul>'));
Check::same('<a href="https://example.com/a?x=1&amp;y=2" title="正常">链接</a>',$cleaner->clean('<a href="https://example.com/a?x=1&amp;y=2" title="正常">链接</a>'));
Check::same('<p>保留文字</p>',$cleaner->clean('<p class="admin" id="location" name="login" style="background:url(javascript:bad())" onclick="bad()">保留文字</p>'));
Check::same('<p>安全</p>',$cleaner->clean('<p>安全<script>window.pwn=1</script><iframe srcdoc="<script>bad()</script>"></iframe><img src="https://evil.invalid/t" onerror="bad()"></p>'));
foreach (['javascript:alert(1)','JAVASCRIPT:alert(1)','jav&#x61;script:alert(1)','data:text/html,<script>bad()</script>','vbscript:msgbox(1)','file:///etc/passwd'] as $url) { Check::same('<a>链接</a>',$cleaner->clean('<a href="'.$url.'">链接</a>')); }
Check::same('<a href="/path">相对</a>',$cleaner->clean('<a href="/path" target="_blank" rel="opener" ping="https://evil.invalid">相对</a>'));
Check::same('<a href="mailto:demo@example.com">邮箱</a>',$cleaner->clean('<a href="mailto:demo@example.com">邮箱</a>'));
$unsafe=['<svg><a xlink:href="javascript:bad()"><text>SVG</text></a></svg>', '<math><mtext><img src=x onerror=bad()></mtext></math>',
    '<form action="https://evil.invalid"><input name="location" autofocus onfocus="bad()"></form>', '<object data="data:text/html,bad"></object><embed src="x"><video src="x"></video>',
    '<!--[if IE]><script>bad()</script><![endif]--><p>x</p>', '<table><tr><td><svg onload="bad()"></svg></td></tr></table>'];
foreach ($unsafe as $input) {
    $result=$cleaner->clean($input); Check::same(false,preg_match('/<(?:script|style|svg|math|form|input|iframe|object|embed|video|img)\b|\bon(?:error|load|focus)\s*=/i',$result)===1);
    Check::same($result,$cleaner->clean($result));
}
Check::same('链接',(new HtmlCleaner(new HtmlPurifierSanitizer(false)))->clean('<a href="https://example.com">链接</a>'));
foreach (["bad\xff", "bad\0", "bad\x01", str_repeat('a',65537)] as $bad) { Check::throws(ValidationException::class,function () use ($cleaner,$bad) { $cleaner->clean($bad); }); }
foreach ([['maximum_nodes'=>16],['maximum_depth'=>8],['maximum_attribute'=>64]] as $budget) {
    $input=isset($budget['maximum_nodes']) ? str_repeat('<p>x</p>',30) : (isset($budget['maximum_depth']) ? str_repeat('<div>',20).'x'.str_repeat('</div>',20) : '<a title="'.str_repeat('x',65).'">x</a>');
    Check::throws(ValidationException::class,function () use ($budget,$input) { (new HtmlCleaner(new HtmlPurifierSanitizer(),new HtmlPolicy($budget)))->clean($input); });
}
$called=false;$probe=new class($called) implements HtmlSanitizer { private $called; public function __construct(bool &$called){$this->called=&$called;} public function sanitize(string $html): string {$this->called=true;return $html;} };
Check::throws(ValidationException::class,function () use ($probe) { (new HtmlCleaner($probe,new HtmlPolicy(['maximum_input'=>8])))->clean(str_repeat('a',9)); });Check::same(false,$called);
$fault=new class implements HtmlSanitizer { public function sanitize(string $html): string { throw new RuntimeException('private adapter detail'); } };
Check::throws(SecurityException::class,function () use ($fault) { (new HtmlCleaner($fault))->clean('<p>x</p>'); });
foreach (["\xff",str_repeat('x',131073)] as $output) { $bad=new class($output) implements HtmlSanitizer {private $output;public function __construct(string $output){$this->output=$output;}public function sanitize(string $html): string{return $this->output;}}; Check::throws(SecurityException::class,function () use ($bad) {(new HtmlCleaner($bad))->clean('x');}); }
Check::throws(SecurityException::class,function () use ($cleaner) { (new HtmlCleaner(new HtmlPurifierSanitizer(),new HtmlPolicy(['maximum_output'=>10])))->clean(str_repeat('&',10)); });
foreach ([['maximum_input'=>null],['maximum_depth'=>129],['maximum_nodes'=>0],['allow_links'=>'yes'],['HTML.Trusted'=>true]] as $bad) { Check::throws(ConfigurationException::class,function () use ($bad){new HtmlPolicy($bad);}); }
$maximum=100;$policy=new HtmlPolicy(['maximum_input'=>&$maximum]);$maximum=1;Check::same(100,$policy->options()['maximum_input']);
foreach (['4.18.0','4.19.0','4.19.1-dev','5.0.0','bogus'] as $version) { Check::same(false,HtmlPurifierSanitizer::supportsVersion($version)); }Check::same(true,HtmlPurifierSanitizer::supportsVersion('4.19.1'));
$factory=SoSecurity\Security::fromArray(['site'=>'html-site','html'=>[]]);Check::same('<p>x</p>',$factory->htmlCleaner()->clean('<p onclick=bad()>x</p>'));
Check::same('manual',array_column($factory->diagnose(),null,'check')['html.render_context']['status']);
Check::throws(ConfigurationException::class,function(){SoSecurity\Security::fromArray(['site'=>'a'])->htmlCleaner();});
Check::throws(ConfigurationException::class,function(){SoSecurity\Security::fromArray(['site'=>'a','html'=>['sanitizer'=>'missing']])->htmlCleaner();});
// The preflight does not change the host's current PHP error handler or libxml error mode.
$handler=set_error_handler(function(){throw new RuntimeException('handler probe');});restore_error_handler();
$mode=libxml_use_internal_errors();$cleaner->clean('<p><b>unclosed');Check::same($mode,libxml_use_internal_errors());
$after=set_error_handler(function(){throw new RuntimeException('handler probe');});restore_error_handler();Check::same($handler,$after);
echo 'PHP '.PHP_VERSION.': '.Check::$assertions." HTML Purifier/budget/config assertions passed\n";
