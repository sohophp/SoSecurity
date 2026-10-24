<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Api\CredentialState;
use SoSecurity\Api\CredentialPolicy;
use SoSecurity\Storage\StorageException;
$policy=new CredentialPolicy();$root=CredentialState::root('owned','tenant','user');$state=CredentialState::empty('tenant','user',str_repeat('1',64),$policy,100,str_repeat('2',32));
$mode=$argv[1]??'root';$oversized=array_fill(0,200000,null);
if($mode==='record'){$state['entries'][str_repeat('3',32)]=$oversized;}else{$state=$oversized;}
unset($oversized);
if(ini_set('memory_limit',(string)(memory_get_usage(true)+1048576))===false){throw new RuntimeException('Cannot set diagnostic memory limit');}
try{CredentialState::read($state,$policy,'owned','tenant',$root,100);throw new RuntimeException('Oversized ledger accepted');}catch(StorageException $error){Check::same('storage.corrupt',$error->reason());}
unset($state);
Check::same(true,CredentialState::fields(['b'=>2,'a'=>1],['a','b']));Check::same(false,CredentialState::fields(['a'=>1,'c'=>2],['a','b']));
Check::same(false,CredentialState::fields(['a'=>1],['a','b']));Check::same(true,CredentialState::fields([],[]));
$state=CredentialState::empty('tenant','user',str_repeat('1',64),$policy,100,str_repeat('2',32));Check::same($state,CredentialState::read($state,$policy,'owned','tenant',$root,100));
echo 'PASS credential state budget '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
