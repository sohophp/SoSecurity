<?php
declare(strict_types=1);
namespace SoSecurity\Support {
    // Fault injection at the actual native-clock boundary, without changing production APIs.
    function hrtime($numeric=false){if($GLOBALS['deadline_throw']){throw new \RuntimeException('private-native-clock-detail');}return $GLOBALS['deadline_value'];}
    function microtime($numeric=false){if($GLOBALS['deadline_throw']){throw new \RuntimeException('private-wall-clock-detail');}return $GLOBALS['deadline_value'];}
}
namespace {
    require __DIR__.'/bootstrap.php';
    function deadlineReason(string $reason,callable $operation):void
    {
        ++Check::$assertions;
        try{$operation();}catch(SoSecurity\Storage\StorageException $error){Check::same($reason,$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'private-')!==false);return;}
        throw new RuntimeException('Expected clock refusal.');
    }
    $GLOBALS['deadline_throw']=false;
    foreach([false,null,'invalid',NAN,INF,-1] as $invalid){
        $GLOBALS['deadline_value']=$invalid;
        deadlineReason('storage.clock',static function():void{new SoSecurity\Support\Deadline(10);});
    }
    $GLOBALS['deadline_throw']=true;
    deadlineReason('storage.clock',static function():void{new SoSecurity\Support\Deadline(10);});
    $GLOBALS['deadline_throw']=false;$GLOBALS['deadline_value']=1000000000;
    $deadline=new SoSecurity\Support\Deadline(10);Check::same(true,$deadline->remaining()>0);
    $GLOBALS['deadline_value']+=function_exists('hrtime')?20000000:0.02;
    deadlineReason('storage.timeout',static function()use($deadline):void{$deadline->check();});
    $GLOBALS['deadline_value']=1000000000;$deadline=new SoSecurity\Support\Deadline(10);$GLOBALS['deadline_value']-=1;
    deadlineReason('storage.timeout',static function()use($deadline):void{$deadline->check();});
    echo 'PASS duration clock failures: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; native/wall-clock invalid numbers and outages refuse, valid elapsed and backwards clocks still expire',PHP_EOL;
}
