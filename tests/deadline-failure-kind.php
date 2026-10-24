<?php
declare(strict_types=1);
namespace SoSecurity\Support {
 function hrtime($numeric=false){return $GLOBALS['duration_sample'];}
 function microtime($numeric=false){return $GLOBALS['duration_sample'];}
}
namespace {
 require __DIR__.'/bootstrap.php';
 $scale=function_exists('hrtime')?1000000000:1;
 $GLOBALS['duration_sample']=100*$scale;$deadline=new SoSecurity\Support\Deadline(1000);
 $GLOBALS['duration_sample']=102*$scale;
 try{$deadline->check('owned.timeout');throw new RuntimeException('Expected elapsed rejection');}catch(SoSecurity\Storage\StorageException $error){Check::same('owned.timeout',$error->reason());Check::same('Security operation exceeded its time budget.',$error->getMessage());Check::same(null,$error->getPrevious());}
 $GLOBALS['duration_sample']=100*$scale;$deadline=new SoSecurity\Support\Deadline(1000);
 $GLOBALS['duration_sample']=99*$scale;Check::same(0.0,$deadline->remaining());
 $GLOBALS['duration_sample']=100*$scale;
 try{$deadline->check('owned.timeout');throw new RuntimeException('Expected backward rejection');}catch(SoSecurity\Storage\StorageException $error){Check::same('owned.timeout',$error->reason());Check::same('Security duration clock moved backwards; the operation budget is expired.',$error->getMessage());Check::same(null,$error->getPrevious());}
 $next=new SoSecurity\Support\Deadline(1000);$next->restrictTo($deadline);
 try{$next->check();throw new RuntimeException('Expected inherited rejection');}catch(SoSecurity\Storage\StorageException $error){Check::same('storage.timeout',$error->reason());Check::same('Security duration clock moved backwards; the operation budget is expired.',$error->getMessage());}
 echo 'PASS deadline failure classification '.Check::$assertions.PHP_EOL;
}
