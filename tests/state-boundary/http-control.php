<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require __DIR__.'/http-source.php';$directory=$argv[1]??'';$action=$argv[2]??'';if(!is_dir($directory)||is_link($directory)||strpos(basename($directory),'sosecurity-test-')!==0||!in_array($action,['inspect','change-role','snapshot','restore'],true)){throw new RuntimeException('Use the owned private HTTP fixture.');}$x=stateHttpLoad($directory);$business=stateHttpBusiness($directory);
if($action==='snapshot'){echo json_encode(stateHttpDatabaseSnapshot($x->e->observer,$business));exit;}
if($action==='restore'){$path=$argv[3]??'';if(!is_file($path)||is_link($path)||(fileperms($path)&0077)!==0){throw new RuntimeException('Use a private owned backup.');}stateHttpDatabaseRestore($x->e->observer,json_decode(file_get_contents($path),true),$business);echo json_encode(['restored'=>true]);exit;}
if($action==='change-role'){$x->boundary->run('owned.http.operator.change',static function()use($x):void{$x->e->pdo->exec("UPDATE account_example SET roles='[\"changed\"]' WHERE subject='user'");});}
$root=$x->inspect();$digest=$x->source->digest();echo json_encode(['format'=>$root['format'],'intent'=>$root['intent'],'documents'=>$business?$x->e->observer->query('SELECT * FROM state_example_documents ORDER BY scope,id')->fetchAll(PDO::FETCH_ASSOC):null,'status'=>$root['status'],'revision'=>$root['revision'],'trusted'=>$root['digest'],'observed'=>$digest,'matches'=>$root['digest']===$digest]);
