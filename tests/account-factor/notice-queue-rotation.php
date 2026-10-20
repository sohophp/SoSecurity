<?php
declare(strict_types=1);
require __DIR__.'/operations-support.php';

managedCase(static function(ManagedEnvironment $e):void{
    $e->registry->initialize('user');$f=purgeFence($e);$source=null;
    $ops=normalOperations($e,$f,null,null,null,static function(string $type,array $review)use(&$source):bool{$source->publish($type,$review['subject'],$review['operation']);return true;});
    $oldKeys=$e->keys;$oldNotices=new SoSecurity\Account\Notifications('old',['old'=>str_repeat('n',32)],$e->clock);
    $source=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$oldKeys,$oldKeys,$e->accounts,$oldNotices,static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},null,$e->clock);
    $source->initialize();$ops->initialize();$review=$ops->review('reencrypt','user','owned-queue-rotation-review');Check::same(true,$ops->execute($review,'owned-queue-rotation',normalProof())['completed']);
    $ids=$e->observer->query("SELECT record_id FROM sosecurity_account_records WHERE kind='notice' ORDER BY record_id")->fetchAll(PDO::FETCH_COLUMN);Check::same(2,count($ids));
    $before=$e->observer->query("SELECT message_id,payload_digest,created_at FROM sosecurity_outbox_records WHERE topic='account.notice' ORDER BY order_no")->fetchAll(PDO::FETCH_ASSOC);Check::same(2,count($before));
    $bothKeys=new SoSecurity\Support\HmacKeys('new',['test'=>str_repeat('s',32),'new'=>str_repeat('x',32)]);
    $newKeys=new SoSecurity\Support\HmacKeys('new',['new'=>str_repeat('x',32)]);
    $bothNotices=new SoSecurity\Account\Notifications('new',['old'=>str_repeat('n',32),'new'=>str_repeat('z',32)],$e->clock);
    $newNotices=new SoSecurity\Account\Notifications('new',['new'=>str_repeat('z',32)],$e->clock);
    $rotating=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$bothKeys,$bothKeys,$e->accounts,$bothNotices,static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},null,$e->clock);
    $after='';$resealed=0;do{$page=$rotating->rotate(1,$after);$resealed+=$page['resealed'];$after=$page['next'];}while(!$page['done']);Check::same(2,$resealed);
    $onlyQueue=static function()use($e,$newKeys):SoSecurity\Outbox\SqlOutbox{return new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$newKeys,static function():bool{return true;},new SoSecurity\Outbox\Policy(['message_age'=>86400,'recovery_age'=>86400,'maximum_entries'=>1000,'maximum_payload_bytes'=>64,'io_milliseconds'=>10000]),$e->clock,static function():bool{return true;});};
    Check::throws(SoSecurity\Storage\StorageException::class,static function()use($onlyQueue):void{$onlyQueue()->claim('tenant','account-factor-notice','worker');});
    Check::same($before,$e->observer->query("SELECT message_id,payload_digest,created_at FROM sosecurity_outbox_records WHERE topic='account.notice' ORDER BY order_no")->fetchAll(PDO::FETCH_ASSOC));
    $queue=new SoSecurity\Outbox\SqlOutbox($e->pdo,'managed-test',str_repeat('e',64),$bothKeys,static function():bool{return true;},new SoSecurity\Outbox\Policy(['message_age'=>86400,'recovery_age'=>86400,'maximum_entries'=>1000,'maximum_payload_bytes'=>64,'io_milliseconds'=>10000]),$e->clock,static function():bool{return true;});
    $after='';$rekeyed=0;do{$page=$queue->maintain('tenant','account-factor-notice','admin',1,$after);$rekeyed+=$page['rekeyed'];$after=$page['next_cursor'];}while(!$page['complete']);Check::same(2,$rekeyed);
    Check::same(['new'],array_values(array_unique($e->observer->query("SELECT seal_key FROM sosecurity_outbox_records WHERE topic='account.notice'")->fetchAll(PDO::FETCH_COLUMN))));
    Check::same($before,$e->observer->query("SELECT message_id,payload_digest,created_at FROM sosecurity_outbox_records WHERE topic='account.notice' ORDER BY order_no")->fetchAll(PDO::FETCH_ASSOC));
    $retired=new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$newKeys,$newKeys,$e->accounts,$newNotices,static function():bool{return true;},static function():bool{return true;},static function():bool{return true;},null,$e->clock);
    $types=[];foreach($ids as $id){$notice=$retired->notificationForDispatch($id);Check::same(true,$notice!==null);$types[]=$notice->notice()->type();}sort($types);Check::same(['factor_management_completed','factor_management_started'],$types);
    $claimed=[];while(($claim=$onlyQueue()->claim('tenant','account-factor-notice','worker'))!==null){$claimed[]=$claim->message()->body();Check::same(true,$onlyQueue()->acknowledge('tenant','account-factor-notice','worker',$claim->token()));}sort($claimed);$expected=$ids;sort($expected);Check::same($expected,$claimed);
});
echo 'PASS factor notice and Outbox key retirement: '.Check::$assertions.' assertions PHP '.PHP_VERSION.'; local '.(($GLOBALS['argv'][1]??'')==='mysql'?'MySQL':'SQLite')." exact two-ledger rotation\n";
