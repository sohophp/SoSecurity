<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$mode=$argv[1] ?? 'absent';
if ($mode==='old') { class HTMLPurifier { const VERSION='4.19.0'; } }
Check::throws(SoSecurity\Exception\DependencyException::class,function(){new SoSecurity\Output\HtmlPurifierSanitizer();});
if (!extension_loaded('dom')) {
    $provider=new class implements SoSecurity\Output\HtmlSanitizer {public function sanitize(string $html): string{return $html;}};
    Check::throws(SoSecurity\Exception\DependencyException::class,function()use($provider){new SoSecurity\Output\HtmlCleaner($provider);});
}
if ($mode==='extensions') {
    require dirname(__DIR__).'/integrations/htmlpurifier/vendor/autoload.php';
    Check::throws(SoSecurity\Exception\DependencyException::class,function(){new SoSecurity\Output\HtmlPurifierSanitizer();});
}
Check::same('&lt;script&gt;',SoSecurity\Output\Escaper::html('<script>'));
echo 'PHP '.PHP_VERSION.': '.Check::$assertions." HTML dependency rejection assertions passed\n";
