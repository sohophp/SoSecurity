<?php
declare(strict_types=1);

/** Include after the consumer's Composer autoloader; construction never installs or changes SQL tables. */
return static function(PDO $pdo,SoSecurity\Storage\FileStore $store,string $directory,string $scratch):SoSecurity\Account\CompositeStateSnapshot{
    $sql=new SoSecurity\Account\SqlStateSnapshot($pdo,'example-account-state',[
        'snapshot_example'=>[
            'columns'=>['scope'=>'bytes:64','subject'=>'bytes:64','enabled'=>'int'],
            'primary'=>['scope','subject'],'where'=>[],'maximum_rows'=>1000,
        ],
    ]);
    $files=new SoSecurity\Account\FileStateSnapshot($pdo,'example-private-state',$directory,$scratch,1000);
    if(!$files->coversStore($store)){throw new SoSecurity\Exception\ConfigurationException('Bind the actual private store directory.','configuration.state_snapshot');}
    return new SoSecurity\Account\CompositeStateSnapshot($pdo,['accounts'=>$sql,'files'=>$files]);
};
