<?php
declare(strict_types=1);
/** Only test observations/fault injection use counters; authority comes from the captured permission row. */
final class CapturedPermissionEvaluator implements SoSecurity\Authorization\SnapshotEvaluator
{
 public $selections=0;public $decisions=0;public $reenter;private $feature;private $case;
 public function __construct(string $feature,string $case){$this->feature=$feature;$this->case=$case;}
 public function selectors(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $fields):array
 {
  ++$this->selections;if($this->reenter!==null){$run=$this->reenter;$this->reenter=null;$run();}
  if($this->case==='selectors-fault'){throw new RuntimeException('PRIVATE-CAPTURED-SELECTORS');}
  return ['permission'=>['table'=>'owned_policy_business','key'=>['scope'=>$actor->scope(),'id'=>'policy'],'columns'=>['owner','amount']]];
 }
 public function decide(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $fields,array $facts):?SoSecurity\Authorization\Decision
 {
  ++$this->decisions;if(in_array($this->case,['budget-before','budget-effect','budget-return'],true)&&$this->decisions===array_search($this->case,['budget-before','budget-effect','budget-return'],true)+1){usleep(31000000);}if($this->case==='fault'){throw new RuntimeException('PRIVATE-CAPTURED-DECISION');}
  if(($this->case==='effect-deny'&&$this->decisions===2)||($this->case==='return-deny'&&$this->decisions===3)){return SoSecurity\Authorization\Decision::deny();}
  $row=$facts['permission']??null;
  if(!$actor->enabled()||$actor->scope()!==$resource->scope()||$resource->type()!=='record'||!is_array($row)||$row['owner']!==$actor->subject()||$row['amount']!==1||($this->feature==='grants'?$action!=='records.write':!in_array($action,['links.issue','links.all','links.revoke','links.revoke_all'],true))){return SoSecurity\Authorization\Decision::deny();}
  return SoSecurity\Authorization\Decision::allow($this->case==='fields'?[]:$fields);
 }
}
