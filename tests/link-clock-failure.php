<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/link-support.php';
$entry=$argv[1]??'issue';$clock=new class implements SoSecurity\Support\Clock{public $failed=false;public function now():int{if($this->failed){throw new RuntimeException('PRIVATE-LINK-CLOCK');}return 100000;}};
$store=new LinkTestStore();$links=new SoSecurity\Link\Links($store,new SoSecurity\Support\HmacKeys('owned',['owned'=>str_repeat('k',32)]),'owned-site',new SoSecurity\Link\Policy('https://links.example.test'),static function():bool{return true;},$clock);
$target=new SoSecurity\Link\Target('record',new SoSecurity\Authorization\Resource('tenant','record','owned','1'),'/records/owned');
$issued=$entry==='verify'?$links->issue($target,true,60):null;
$store->after=static function()use($clock):void{$clock->failed=true;};$rejected=false;
try{if($entry==='verify'){$links->verify($target,$issued->url());}else{$links->issue($target,true,60);}}catch(SoSecurity\Storage\StorageException $error){$rejected=true;Check::same('link.clock',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE')!==false);}
Check::same(true,$rejected);Check::same(null,$store->states[SoSecurity\Link\State::key('owned-site',$target)]);
echo 'PASS link clock failure '.$entry.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
