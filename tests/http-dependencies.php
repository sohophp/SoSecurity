<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
if (extension_loaded('curl')) { echo "NOT RUN missing cURL: invoke with a minimal ini\n"; exit(0); }
Check::throws(SoSecurity\Exception\DependencyException::class,function () { new SoSecurity\Http\Outbound\Client(new SoSecurity\Http\Outbound\Policy(['hosts'=>['api.example.com']])); });
Check::same(true,(new SoSecurity\Http\Redirects('https://site.example'))->allows('/home'));
Check::same(true,(new SoSecurity\Http\Cors(['https://client.example']))->evaluate('GET','https://client.example')->allowed());
echo 'PHP '.PHP_VERSION.': '.Check::$assertions." missing HTTP dependency assertions passed\n";
