<?php
declare(strict_types=1);
require_once __DIR__.'/crash-load.php';
$path=$argv[1]??'';
if(!is_file($path)||(fileperms($path)&0077)!==0){throw new RuntimeException('Use the owned private fence rollback probe.');}
$m=json_decode(file_get_contents($path),true);$x=crashLoad($m['target'],false);
Check::same($m['source'],$x->source->fingerprint());Check::same($m['before'],$x->inspect());
$fence=new SoSecurity\Account\LocalEpochFence($x->e->directory.'/entry-bound-fence','managed-test','tenant',str_repeat('e',64),$x->e->keys,'witnessPersist',5000,$x->boundary);
if($m['restored']){
    Check::same(false,$x->source->digest()===$m['before']['digest']);$called=0;$files=entryFiles($x);
    witnessReason('account.witness_stale',static function()use($x,$fence,&$called):void{$x->boundary->run('owned.fresh.rollback',static function()use($fence,&$called):void{$fence->work(static function()use(&$called):void{++$called;});});});
    Check::same(0,$called);Check::same($files,entryFiles($x));
}else{Check::same($m['before']['digest'],$x->source->digest());}
Check::same($m['before'],$x->inspect());
echo 'PASS fresh fence source reader: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; restored='.($m['restored']?'yes':'no')."; no authority provisioning or worker effect\n";
