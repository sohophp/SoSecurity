<?php
declare(strict_types=1);
final class AddressCapturedEvaluator implements SoSecurity\Authorization\SnapshotEvaluator
{
 public $lastAllowed;public $calls=0;public $selections=0;public $hook;public $hookAt;public $denyAt;public $faultAt;private $case;
 public function __construct(string $case){$this->case=$case;}
 public function selectors(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $fields):array
 {
  ++$this->selections;if($this->case==='selector-fault'){throw new RuntimeException('PRIVATE-ADDRESS-SELECTOR');}
  return ['permission'=>['table'=>'owned_address_permissions','key'=>['scope'=>$actor->scope(),'subject'=>$actor->subject()],'columns'=>['allowed']]];
 }
 public function decide(SoSecurity\Auth\Account $actor,string $action,SoSecurity\Authorization\Resource $resource,array $fields,array $facts):?SoSecurity\Authorization\Decision
 {
  $this->lastAllowed=$facts['permission']['allowed']??null;++$this->calls;if($this->hook!==null&&($this->hookAt===null||$this->calls===$this->hookAt)){$call=$this->hook;$this->hook=null;$call();}if($this->case==='fault'||$this->calls===$this->faultAt){throw new RuntimeException('PRIVATE-ADDRESS-DECISION');}
  if($this->calls===$this->denyAt){return SoSecurity\Authorization\Decision::deny();}
  if(!$actor->enabled()||!in_array('member',$actor->roles(),true)||$actor->scope()!==$resource->scope()||$resource->type()!=='account'||$resource->id()!==$actor->subject()||!in_array($action,['account.address.request','account.address.complete'],true)||!isset($facts['permission']['allowed'])||$facts['permission']['allowed']!==1){return SoSecurity\Authorization\Decision::deny();}
  return SoSecurity\Authorization\Decision::allow($this->case==='fields'?[]:$fields);
 }
}
