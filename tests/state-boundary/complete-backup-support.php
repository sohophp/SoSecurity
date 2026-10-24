<?php
declare(strict_types=1);
function backupTypes():array
{
    $account=['scope'=>'bytes:256','subject'=>'bytes:256','credential_version'=>'bytes:256','address_version'=>'bytes:256','address'=>'bytes:320','password'=>'nullable_bytes:4096','status'=>'bytes:16','verified'=>'int','mfa_required'=>'int','roles'=>'bytes:4096'];
    $records=SoSecurity\Account\Ledger::recordTypes();$records['payload']='blob:16384';$outbox=SoSecurity\Outbox\Schema::recordTypes();$outbox['payload_body']='blob:1048576';
    return ['account_example'=>$account,'factor_migration_audit'=>['operation'=>'bytes:64','phase'=>'bytes:32','context_digest'=>'digest'],
        'sosecurity_account_roots'=>SoSecurity\Account\Ledger::rootTypes(),'sosecurity_account_records'=>$records,
        'sosecurity_outbox_roots'=>SoSecurity\Outbox\Schema::rootTypes(),'sosecurity_outbox_records'=>$outbox,
        'entry_worker_audit'=>['operation'=>'digest','context_digest'=>'digest']];
}
function completeBackup(EntryEnvironment $x):array
{
    $rows=[];foreach(backupTypes() as $table=>$types){$q=$x->e->pdo->query('SELECT * FROM '.$table);$rows[$table]=$q->fetchAll(PDO::FETCH_ASSOC);$q->closeCursor();}
    return ['rows'=>$rows,'files'=>entryFiles($x),'digest'=>$x->source->digest()];
}
function completeRestore(EntryEnvironment $x,array $backup):void
{
    $pdo=$x->e->pdo;$quote=$pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'?'`':'"';$pdo->beginTransaction();
    try{
        foreach(backupTypes() as $table=>$types){
            $pdo->exec('DELETE FROM '.$table);
            foreach($backup['rows'][$table] as $row){
                $columns=array_keys($row);$q=$pdo->prepare('INSERT INTO '.$table.'('.$quote.implode($quote.','.$quote,$columns).$quote.') VALUES('.implode(',',array_fill(0,count($columns),'?')).')');
                foreach(array_values($columns) as $i=>$column){$value=$row[$column];$type=$types[$column];if($type==='int'){$value=SoSecurity\Support\SqlSchema::integer($value);}$q->bindValue($i+1,$value,$value===null?PDO::PARAM_NULL:($type==='int'?PDO::PARAM_INT:(strpos($type,'blob:')===0?PDO::PARAM_LOB:PDO::PARAM_STR)));}
                $q->execute();$q->closeCursor();
            }
        }
        $pdo->commit();
    }catch(Throwable $error){if($pdo->inTransaction()){$pdo->rollBack();}throw $error;}
    entryRestore($x,$backup['files']);Check::same($backup['digest'],$x->source->digest());
}
