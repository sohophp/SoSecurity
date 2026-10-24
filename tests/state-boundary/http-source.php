<?php
declare(strict_types=1);
require_once __DIR__.'/crash-load.php';
/** Test host only, same new actual PDOs/services with explicit ownership before any MySQL access. */
function stateHttpLoad(string $directory):EntryEnvironment
{
    $real=realpath($directory);if($real!==$directory||is_link($directory)||!is_dir($directory)||(fileperms($directory)&0077)!==0){throw new RuntimeException('Use a canonical owned private host.');}$m=json_decode(file_get_contents($directory.'/http-host.json'),true);if(($m['directory']??null)!==$directory||!in_array($m['backend']??null,['sqlite','mysql'],true)){throw new RuntimeException('Use the exact owned host metadata.');}
    if($m['backend']==='mysql'){$socket=getenv('SOSECURITY_TEST_MYSQL_SOCKET');if(!is_string($socket)||!preg_match('~\A/tmp/sosecurity-mysql-[A-Za-z0-9_-]+/mysql\.sock\z~D',$socket)||is_link(dirname($socket))||!is_file(dirname($socket).'/account-test-owner')){throw new RuntimeException('Use only the controller-owned MySQL socket.');}}
    $m['time']=time();return crashLoad($m,false);
}
/** Byte-preserving backup of exactly the declared owned authentication tables; no schema or authority. */
function stateHttpBusiness(string $directory):bool{return (json_decode(file_get_contents($directory.'/http-host.json'),true)['business']??false)===true;}
function stateHttpTables(bool $business=false):array{return array_merge(['account_example','factor_migration_audit','sosecurity_account_roots','sosecurity_account_records','sosecurity_outbox_roots','sosecurity_outbox_records','entry_worker_audit'],$business?['state_example_documents']:[]);}
function stateHttpDatabaseSnapshot(PDO $pdo,bool $business=false):array
{
    $out=[];$pdo->beginTransaction();try{foreach(stateHttpTables($business) as $name){$rows=$pdo->query('SELECT * FROM `'.$name.'`')->fetchAll(PDO::FETCH_ASSOC);$encoded=[];foreach($rows as $row){$copy=[];foreach($row as $key=>$value){if($value===null){$copy[$key]=['type'=>'null','value'=>null];}elseif(is_int($value)){$copy[$key]=['type'=>'int','value'=>$value];}elseif(is_string($value)){$copy[$key]=['type'=>'bytes','value'=>base64_encode($value)];}else{throw new RuntimeException('Unsupported owned SQL value.');}}$encoded[]=$copy;}usort($encoded,static function(array $a,array $b):int{return strcmp(json_encode($a),json_encode($b));});$out[$name]=$encoded;}$pdo->commit();}catch(Throwable $e){if($pdo->inTransaction()){$pdo->rollBack();}throw $e;}return $out;
}
function stateHttpDatabaseRestore(PDO $pdo,array $data,bool $business=false):void
{
    if(array_keys($data)!==stateHttpTables($business)){throw new RuntimeException('Only exact owned table backups.');}$pdo->beginTransaction();try{foreach($data as $table=>$rows){if(!is_array($rows)||count($rows)>10000){throw new RuntimeException('Bounded owned rows only.');}$pdo->exec('DELETE FROM `'.$table.'`');foreach($rows as $row){$columns=array_keys($row);foreach($columns as $name){if(!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$name)){throw new RuntimeException('Fixed SQL column names only.');}}$q=$pdo->prepare('INSERT INTO `'.$table.'` (`'.implode('`,`',$columns).'`) VALUES ('.implode(',',array_fill(0,count($columns),'?')).')');$n=1;foreach($row as $value){$type=$value['type']??'';$v=$value['value']??null;if($type==='int'&&is_int($v)){$q->bindValue($n++,$v,PDO::PARAM_INT);}elseif($type==='null'&&$v===null){$q->bindValue($n++,null,PDO::PARAM_NULL);}elseif($type==='bytes'&&is_string($v)&&($raw=base64_decode($v,true))!==false){$q->bindValue($n++,$raw,PDO::PARAM_LOB);}else{throw new RuntimeException('Invalid owned SQL value.');}}$q->execute();$q->closeCursor();}}$pdo->commit();}catch(Throwable $e){if($pdo->inTransaction()){$pdo->rollBack();}throw $e;}
}
