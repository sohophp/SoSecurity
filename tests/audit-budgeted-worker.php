<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

$clock=new TestClock();
$store=new SoSecurity\Storage\FileStore($argv[1],'audit-process',$clock);
$audit=new SoSecurity\Audit\AuditLogger(new SoSecurity\Audit\BudgetedSink($store,'shared-site',3,60,
    static function(array $record):void {},$clock),str_repeat('A',32));
try {
    $audit->record('login.failed','tenant',$argv[2],['allowed'=>false]);
    echo "ACCEPTED\n";
} catch (SoSecurity\Exception\SecurityException $failure) {
    if ($failure->reason()!=='audit.capacity') { throw $failure; }
    echo "REFUSED\n";
}
