<?php
declare(strict_types=1);
namespace SoSecurity\Account {
    // Deterministic owned-directory replacement between validation and iterator construction.
    function realpath($path) {
        $value=\realpath($path);
        if(($GLOBALS['owned_quarantine_move']??null)===$path){$GLOBALS['owned_quarantine_move']=null;if(!\rename($path,$path.'.moved')){throw new \RuntimeException('Owned directory race could not be prepared');}}
        return $value;
    }
}
namespace {
    require dirname(__DIR__).'/bootstrap.php';
    $directory=privateDirectory();$pdo=null;
    try{
        mkdir($directory.'/spool',0700);mkdir($directory.'/web',0700);$pdo=new PDO('sqlite:'.$directory.'/state.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
        $source=new SoSecurity\Account\QuarantineStateSnapshot($pdo,'owned-race',$directory.'/spool',$directory.'/web',new SoSecurity\Upload\Policy(['extensions'=>['txt']]));
        $GLOBALS['owned_quarantine_move']=$directory.'/spool';
        try{$source->digest();throw new RuntimeException('Directory replacement accepted');}catch(SoSecurity\Storage\StorageException $error){Check::same('account.quarantine_snapshot_corrupt',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),$directory)!==false);}
        echo 'PASS quarantine directory race privacy: '.Check::$assertions.' assertions PHP '.PHP_VERSION.PHP_EOL;
    }finally{$GLOBALS['owned_quarantine_move']=null;$pdo=null;foreach(['spool','spool.moved','web'] as $name){if(is_dir($directory.'/'.$name)){cleanDirectory($directory.'/'.$name);}}cleanDirectory($directory);}
}
