<?php
declare(strict_types=1);
use SoSecurity\Authorization as Z;
use SoSecurity\Exception\SecurityException;
$credential=$api->issue('tenant','fresh-user',$token,'Owned business return',['records:write']);
$boundary->run('owned.business.seed',static function()use($pdo):void{$pdo->exec("INSERT INTO owned_native_business VALUES ('owned',1)");});
$rules=new Z\RolePolicy(['records.write'=>['type'=>'record','roles'=>['operator'],'fields'=>['amount'],'owner_attribute'=>'owner']]);
$tables=['owned_native_business'=>['columns'=>['id'=>'bytes:64','amount'=>'int'],'primary'=>['id']]];
$nativeFinalHook=static function()use($mode,&$auditRequestAllowed,&$auditScopes,$clock,$credential):void{
 if($mode==='business-budget-after'){usleep(5100000);}
 if($mode==='business-guard'){$auditRequestAllowed=false;}
 if($mode==='business-scope'){$auditScopes=[];}
 if($mode==='business-expiry'){$clock->time=$credential->metadata()->expiresAt();}
};
$rejected=false;
try{
 $value=$api->withAuthorization('tenant','Bearer '.$credential->token(),'records:write',$pdo,$tables,$rules,
  static function(PDO $db,SoSecurity\Api\VerifiedCredential $proof):SoSecurity\Operation\Intent{return new SoSecurity\Operation\Intent('records.write',new Z\Resource('tenant','record','owned','1',['owner'=>'fresh-user']),['amount'=>2],['amount']);},
  static function(PDO $db)use($mode):int{$db->exec("UPDATE owned_native_business SET amount=2 WHERE id='owned'");if($mode==='business-budget-before'){usleep(5100000);}return 2;});
 if($mode==='business-normal'){Check::same(2,$value);}
}catch(SecurityException $error){$rejected=true;Check::same($mode==='business-budget-before'?'account.completion_unknown':($mode==='business-budget-after'?'account.operation_timeout':'api_credentials.denied'),$error->reason());if($mode==='business-budget-before'){Check::same('sql.timeout',$error->getPrevious()->reason());}else{Check::same(null,$error->getPrevious());}}
Check::same($mode!=='business-normal',$rejected);
Check::same($mode==='business-budget-before'?1:2,(int)$pdo->query("SELECT amount FROM owned_native_business WHERE id='owned'")->fetchColumn());
Check::same($mode==='business-budget-before'?'pending':'current',$inspect()['status']);
echo 'PASS native business return '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
