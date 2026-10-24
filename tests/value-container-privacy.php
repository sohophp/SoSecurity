<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Uri;
use SoSecurity\Validation\Validator;

$marker='SYNTHETIC-PRIVATE-CONTAINER-VALUE';
$mode=$argv[1] ?? '';
if($mode==='validation'){
    $result=(new Validator(['password'=>['type'=>'string','max'=>64]]))->validate(['password'=>$marker]);
    Check::same(true,$result->valid());Check::same($marker,$result->data()['password']);
    $objects=[$result];
}elseif($mode==='uri'){
    $uri=Uri::parse('https://example.com/'.$marker.'?token='.$marker.'#'.$marker,true);
    Check::same('/'.$marker.'?token='.$marker,$uri->target());
    Check::same('https://example.com/'.$marker.'?token='.$marker,$uri->withoutFragment()->url());
    Check::same('https://example.com/next',$uri->resolve('/next')->url());
    $objects=[$uri,$uri->withoutFragment()];
}else{throw new RuntimeException('Unknown value privacy case.');}
foreach($objects as $value){
    Check::same(false,strpos(var_export($value,true),$marker)!==false);
    Check::same(false,strpos(print_r($value,true),$marker)!==false);
    ob_start();var_dump($value);$dump=ob_get_clean();Check::same(false,strpos($dump,$marker)!==false);
    Check::throws(ConfigurationException::class,static function()use($value):void{serialize($value);});
    $class=get_class($value);$forged='O:'.strlen($class).':"'.$class.'":0:{}';
    Check::throws(ConfigurationException::class,static function()use($forged):void{unserialize($forged);});
}
echo 'PASS value-container privacy '.$mode.': '.Check::$assertions.' assertions PHP '.PHP_VERSION."; explicit values retained, diagnostic/export/cache paths protected\n";
