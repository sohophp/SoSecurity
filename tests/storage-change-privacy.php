<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Storage\Change;
use SoSecurity\Exception\ConfigurationException;
$mode=$argv[1]??'export';$state=['secret'=>'OWNED-STATE-SECRET'];$result=(object)['secret'=>'OWNED-RESULT-SECRET'];$change=new Change($state,123,$result);
Check::same($state,$change->value());Check::same(123,$change->expiresAt());Check::same($result,$change->result());
if($mode==='serialize'){try{serialize($change);throw new RuntimeException('Serialized state accepted');}catch(ConfigurationException $error){Check::same('configuration.storage_serialization',$error->reason());}}
elseif($mode==='wakeup'){try{unserialize('O:25:"SoSecurity\\Storage\\Change":0:{}');throw new RuntimeException('Unserialized state accepted');}catch(ConfigurationException $error){Check::same('configuration.storage_serialization',$error->reason());}}
else{
 if($mode==='export'){$output=var_export($change,true);}elseif($mode==='dump'){ob_start();var_dump($change);$output=ob_get_clean();}elseif($mode==='print'){$output=print_r($change,true);}else{throw new RuntimeException('Unknown mode');}
 Check::same(false,strpos($output,'OWNED-STATE-SECRET')!==false);Check::same(false,strpos($output,'OWNED-RESULT-SECRET')!==false);
}
Check::throws(ConfigurationException::class,static function()use($change):void{$change->value=[];});
Check::same(null,(new Change(null,0,null))->value());Check::same(null,(new Change(null,0,null))->result());
echo 'PASS storage change privacy '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
