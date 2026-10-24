<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Storage\Codec;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
Codec::encode(new Change([],0,null));$mode=$argv[1]??'value';
if($mode==='value'){$state=['owned'=>str_repeat('x',4194304)];}
elseif($mode==='key'){$state=[str_repeat('k',4194304)=>true];}
elseif($mode==='aggregate'){$state=array_fill(0,1024,str_repeat('x',4096));}
else{throw new RuntimeException('Unknown mode');}
if(ini_set('memory_limit',(string)(memory_get_usage(true)+1048576))===false){throw new RuntimeException('Cannot set diagnostic memory limit');}
try{Codec::encode(new Change($state,0,null));throw new RuntimeException('Oversized state accepted');}catch(StorageException $error){Check::same('storage.encoding',$error->reason());}
unset($state);
$empty=Codec::encode(new Change(['k'=>''],0,null));$state=['k'=>str_repeat('x',65536-strlen($empty))];$encoded=Codec::encode(new Change($state,0,null));Check::same(65536,strlen($encoded));Check::same($state,Codec::decode($encoded,0));unset($state,$encoded);
$state=['中文'=>['slash'=>'/','controls'=>"\n\t",'values'=>[1,true,null,1.5]]];Check::same($state,Codec::decode(Codec::encode(new Change($state,0,null)),0));
try{Codec::encode(new Change(['k'=>str_repeat("\n",40000)],0,null));throw new RuntimeException('Escaped overflow accepted');}catch(StorageException $error){Check::same('storage.encoding',$error->reason());}
echo 'PASS storage encoding budget '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
