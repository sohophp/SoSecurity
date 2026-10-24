<?php
declare(strict_types=1);
/** Fixed owned test host profile, reviewed against its SQL resources and audit DDL. No runtime inference. */
function ownedAuthenticationSource(ManagedEnvironment $e,array $extra=[],?string $accountScope=null,?array &$parts=null,bool $existing=false,?SoSecurity\Api\KeyRing $signingKeys=null,int $filesCap=100000):SoSecurity\Account\StateSnapshot
{
    $definitions=[
        'account_example'=>['columns'=>['scope'=>'bytes:256','subject'=>'bytes:256','credential_version'=>'bytes:256','address_version'=>'bytes:256','address'=>'bytes:320','password'=>'nullable_bytes:4096','status'=>'bytes:16','verified'=>'int','mfa_required'=>'int','roles'=>'bytes:4096'],'primary'=>['scope','subject']],
        'factor_migration_audit'=>['columns'=>['operation'=>'bytes:64','phase'=>'bytes:32','context_digest'=>'digest'],'primary'=>['operation','phase','context_digest']],
        'sosecurity_account_roots'=>['columns'=>SoSecurity\Account\Ledger::rootTypes(),'primary'=>['namespace']],
        'sosecurity_account_records'=>['columns'=>SoSecurity\Account\Ledger::recordTypes(),'primary'=>['namespace','record_id']],
        'sosecurity_outbox_roots'=>['columns'=>SoSecurity\Outbox\Schema::rootTypes(),'primary'=>['namespace']],
        'sosecurity_outbox_records'=>['columns'=>SoSecurity\Outbox\Schema::recordTypes(),'primary'=>['namespace','key_hash']],
    ];
    foreach($extra as $table=>$definition){if(isset($definitions[$table])){throw new RuntimeException('Duplicate owned source declaration.');}$definitions[$table]=$definition;}
    $definitions['sosecurity_account_records']['columns']['payload']='blob:16384';$definitions['sosecurity_outbox_records']['columns']['payload_body']='blob:1048576';
    foreach($definitions as &$definition){$definition['where']=[];$definition['maximum_rows']=10000;}unset($definition);
    if($accountScope!==null){SoSecurity\Support\Guard::label($accountScope);$definitions['account_example']['where']=['scope'=>$accountScope];}
    if($e->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='sqlite'){$definitions['factor_migration_audit']['sqlite_declarations']=['operation'=>'VARCHAR(64)','phase'=>'VARCHAR(32)','context_digest'=>'VARCHAR(64)'];}
    $sql=new SoSecurity\Account\SqlStateSnapshot($e->pdo,'owned-complete-authentication',$definitions,30000);
    foreach($existing?[]:['snapshot-scratch','independent-witness'] as $name){mkdir($e->directory.'/'.$name,0700);}
    $files=new SoSecurity\Account\FileStateSnapshot($e->pdo,'owned-authentication-physical',$e->directory.'/factors',$e->directory.'/snapshot-scratch',$filesCap===0?max(1,count(glob($e->directory.'/factors/*.json'))):$filesCap,30000);
    $parts=['sql'=>$sql,'files'=>$files];
    $sources=['complete-sql'=>$sql,'sessions-and-factors'=>$files];foreach(['authority'=>'fence_legacy','entry-bound-fence'=>'fence_bound','entry-next-fence'=>'fence_next'] as $dir=>$part){$path=$e->directory.'/'.$dir;if(!$existing&&!is_dir($path)){mkdir($path,0700);}$parts[$part]=new SoSecurity\Account\FenceStateSnapshot($e->pdo,'owned-'.$part,$path,128,30000);$sources[$part]=$parts[$part];}if($signingKeys!==null){$parts['keys']=new SoSecurity\Account\KeyRingStateSnapshot($e->pdo,'owned-api-key-configuration',$signingKeys,new SoSecurity\Api\SignaturePolicy(['origin'=>'https://api.example.test','clock_skew'=>0]));$sources['hmac-keys']=$parts['keys'];}return new SoSecurity\Account\CompositeStateSnapshot($e->pdo,$sources,30000);
}
