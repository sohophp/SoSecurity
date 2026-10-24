<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Auth\DeviceRiskPolicy;
use SoSecurity\Exception\ConfigurationException;
$policy=new DeviceRiskPolicy();$signals=array_fill(0,100000,false);
Check::throws(ConfigurationException::class,static function()use($policy,$signals):void{$policy->decide($signals);});
Check::same(true,memory_get_peak_usage(false)<8388608);
echo 'PASS device risk budget: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; malformed signal count refused before copying/sorting\n";
