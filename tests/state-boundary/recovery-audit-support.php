<?php
declare(strict_types=1);
require __DIR__.'/account-resolution-support.php';
function recoveryAuditCase(callable $work,?callable $persist=null):void
{
    $audit=null;retirementCase(static function(EntryEnvironment $x,EntryEnvironment $op,SoSecurity\Account\StateRetirementControl $control)use($work,&$audit):void{$work($x,$op,$control,$audit);},static function(ManagedEnvironment $e)use(&$audit,$persist):EntryEnvironment{
        $dir=$e->directory.'/recovery-audit';mkdir($dir,0700);$audit=new SoSecurity\Account\StateRecoveryAudit($dir,$e->keys,static function($h)use($dir,$persist):bool{witnessPersist($h,$dir);return $persist===null||$persist($h)===true;});
        return new EntryEnvironment($e,false,2,null,30000,$audit);
    });
}
function recoveryAuditReload(EntryEnvironment $x,SoSecurity\Account\LocalStateWitness $old,SoSecurity\Account\StateRecoveryAudit $audit):SoSecurity\Account\LocalStateWitness
{
    $e=$x->e;return new SoSecurity\Account\LocalStateWitness($e->pdo,$e->directory.'/independent-witness','managed-test','tenant',str_repeat('e',64),$e->keys,$x->source,static function($h)use($e):bool{return witnessPersist($h,$e->directory.'/independent-witness');},30000,$old->format(),$old->generation(),$audit);
}
function recoveryAuditCount(SoSecurity\Account\LocalStateWitness $w):int{$cursor=null;$count=0;$heads=[];do{$p=$w->recoveryHistory('witnessBudget',$cursor);Check::same(true,count($p['events'])>=1&&count($p['events'])<=4);foreach($p['events'] as $v){Check::same(false,isset($heads[$v['head']]));$heads[$v['head']]=true;++$count;}$cursor=$p['cursor'];}while($cursor!==null);return $count;}
