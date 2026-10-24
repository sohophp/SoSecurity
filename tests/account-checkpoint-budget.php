<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Account\Ledger;
use SoSecurity\Exception\ConfigurationException;
$mode=$argv[1]??'normal';
if($mode==='oversize'){
    $row=['namespace'=>str_repeat('a',64)];for($i=0;$i<60000;++$i){$row[$i]=null;}
    Check::throws(ConfigurationException::class,static function()use($row):void{Ledger::digest($row);});
}else{
    $row=['namespace'=>str_repeat('a',64),'format'=>1,'epoch'=>str_repeat('b',64),'policy'=>str_repeat('c',64),'entries'=>0,'revision'=>1,'history_digest'=>str_repeat('d',64),'created_at'=>100,'observed_at'=>100,'seal_key'=>'key','seal'=>str_repeat('e',64)];
    $expected=hash('sha256','SoSecurity.Account.Checkpoint.1.'.json_encode($row,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));Check::same($expected,Ledger::digest($row));
    foreach(['missing','extra','order','type','length'] as $case){$bad=$row;if($case==='missing'){unset($bad['seal']);}if($case==='extra'){$bad['other']=null;}if($case==='order'){$bad=array_reverse($bad,true);}if($case==='type'){$bad['entries']='0';}if($case==='length'){$bad['seal']=str_repeat('e',65);}
        Check::throws(ConfigurationException::class,static function()use($bad):void{Ledger::digest($bad);});}
}
echo 'PASS pure account checkpoint shape: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; no SQL, authority or recovery calls\n";
