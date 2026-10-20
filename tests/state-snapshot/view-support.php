<?php
declare(strict_types=1);
require __DIR__.'/support.php';
function viewSources(InboxTestConnection $pdo,string $root):array
{
    $state=$root.'/physical';$scratch=$root.'/scratch';mkdir($state,0700);mkdir($scratch,0700);
    $sql=snapshotSource($pdo);$files=new SoSecurity\Account\FileStateSnapshot($pdo,'owned-view-files',$state,$scratch,10000,30000);
    $composite=new SoSecurity\Account\CompositeStateSnapshot($pdo,['sql'=>$sql,'physical'=>$files],30000);
    $put=static function(string $name,string $raw)use($state):void{file_put_contents($state.'/'.$name,$raw);chmod($state.'/'.$name,0600);};
    return [$sql,$files,$composite,$state,$scratch,$put];
}
function viewRow(int $id=1):array{return ['table'=>'snapshot_test','key'=>['scope'=>'tenant','id'=>$id],'columns'=>['tag','password']];}
function viewSelections():array{return ['sql'=>['actor'=>viewRow()],'physical'=>['session'=>str_repeat('a',64).'.json']];}
