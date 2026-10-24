<?php
declare(strict_types=1);
/** Test-only timings. Never retains SQL text, parameters, accounts or credentials. */
final class NativeAuditTiming
{
 public static $active=false;public static $start=0;public static $stats=[];public static $marks=[];public static $callers=[];
 public static function begin():void{if(!function_exists('hrtime')){throw new RuntimeException('A real monotonic diagnostic clock is required');}self::$start=hrtime(true);self::$stats=[];self::$marks=[];self::$callers=[];self::$active=true;}
 public static function mark(string $operation,string $phase):void{if(!self::$active){return;}if(count(self::$marks)>=64){throw new RuntimeException('Diagnostic marker budget exceeded');}self::$marks[]=['operation'=>$operation,'phase'=>$phase,'seconds'=>(hrtime(true)-self::$start)/1000000000];}
 public static function finish():array{$end=hrtime(true);self::$active=false;return ['seconds'=>($end-self::$start)/1000000000,'sql'=>self::$stats,'phases'=>self::$marks,'callers'=>self::$callers];}
}
final class NativeAuditTimingStatement extends PDOStatement
{
 protected function __construct(){}
 public function execute($params=null):bool{
  if(!NativeAuditTiming::$active){return $params===null?parent::execute():parent::execute($params);}
  $kind=strpos($this->queryString,'information_schema')!==false||strpos($this->queryString,'sqlite_master')!==false||strpos($this->queryString,'pragma_table_info')!==false?'metadata':(strpos($this->queryString,'__sw_valid')!==false?'snapshot_rows':(strpos($this->queryString,'sosecurity_audit_')!==false?'audit':'other'));
  if($kind==='metadata'){foreach(['REFERENTIAL_CONSTRAINTS'=>'foreign_keys','KEY_COLUMN_USAGE'=>'foreign_keys','COLUMNS'=>'columns','STATISTICS'=>'indexes','TRIGGERS'=>'triggers','TABLES'=>'tables'] as $match=>$category){if(strpos($this->queryString,'information_schema.'.$match)!==false){$kind=$category;break;}}}
  // Fixed code identifiers only: no SQL, parameters, file paths, objects or argument values.
  $frames=[];foreach(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS,9) as $frame){if(isset($frame['class'])){$frames[]=$frame['class'].'::'.$frame['function'];}}
  $caller=$kind.'|'.implode('>',$frames);if(!isset(NativeAuditTiming::$callers[$caller])&&count(NativeAuditTiming::$callers)>=128){$caller='overflow';}
  $at=hrtime(true);try{return $params===null?parent::execute():parent::execute($params);}finally{
   if(!isset(NativeAuditTiming::$stats[$kind])){NativeAuditTiming::$stats[$kind]=['count'=>0,'seconds'=>0.0];}++NativeAuditTiming::$stats[$kind]['count'];$seconds=(hrtime(true)-$at)/1000000000;NativeAuditTiming::$stats[$kind]['seconds']+=$seconds;
   if(!isset(NativeAuditTiming::$callers[$caller])){NativeAuditTiming::$callers[$caller]=['count'=>0,'seconds'=>0.0];}++NativeAuditTiming::$callers[$caller]['count'];NativeAuditTiming::$callers[$caller]['seconds']+=$seconds;
  }
 }
}
