<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Audit\BudgetedSink;
use SoSecurity\Audit\MetricsSink;
use SoSecurity\Audit\RecentEvents;
use SoSecurity\Audit\SqlSink;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\FileStore;
$directory=privateDirectory();
try {
    $clock=new TestClock(); $store=new FileStore($directory,'audit-budget',$clock); $writes=0;
    $writer=static function()use(&$writes):void{++$writes;};
    switch($argv[1] ?? '') {
        case 'budgeted': $sink=new BudgetedSink($store,'site',2,60,$writer,$clock);break;
        case 'metrics': $sink=new MetricsSink($store,'site',['login.failed'=>'authentication'],['authentication'=>1],2,60,$writer,$clock);break;
        case 'recent': $sink=new RecentEvents($store,'site',str_repeat('K',32),2,60,$writer,static function():bool{return true;},$clock);break;
        case 'sql': $sink=new SqlSink(new PDO('sqlite:'.$directory.'/audit.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]),'site',2,60,$clock);break;
        default: throw new LogicException('Unknown audit sink');
    }
    $files=glob($directory.'/*');
    $record=['time'=>100000,'event'=>'login.failed','scope'=>'tenant','subject'=>null,'context'=>[]];
    for($i=0;$i<60000;++$i){$record[$i]=null;}
    Check::throws(ConfigurationException::class,static function()use($sink,$record):void{$sink($record);});
    Check::same(0,$writes);
    Check::same($files,glob($directory.'/*'));
    echo 'PASS bounded audit record before storage/writer: '.Check::$assertions.' assertions PHP '.PHP_VERSION."\n";
}finally{cleanDirectory($directory);}
