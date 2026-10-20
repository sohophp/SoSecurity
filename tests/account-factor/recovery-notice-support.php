<?php
declare(strict_types=1);
require __DIR__.'/closed-support.php';

function replacementNoticeSource(ManagedEnvironment $e,callable $publish):SoSecurity\Account\FactorNotices
{
    return new SoSecurity\Account\FactorNotices($e->pdo,'managed-test','tenant',str_repeat('e',64),$e->keys,$e->keys,$e->accounts,new SoSecurity\Account\Notifications('notice',['notice'=>str_repeat('n',32)],$e->clock),static function():bool{return true;},$publish,static function():bool{return true;},null,$e->clock);
}

function replacementNoticeService(ManagedEnvironment $e,SoSecurity\Account\LocalEpochFence $f,array &$receipt,?SoSecurity\Account\FactorNotices &$source,callable $publish):SoSecurity\Account\FactorRecovery
{
    $service=switchService($e,switchApproval($receipt),static function(string $type,$before,$after,string $selector)use(&$source):bool{
        if(!$before instanceof SoSecurity\Account\AccountRecord){throw new RuntimeException('Owned current account required.');}
        $source->publish($type,$before->account()->subject(),$selector);return true;
    },null,null,$f);
    $source=replacementNoticeSource($e,$publish);$source->initialize();$service->initialize();return $service;
}

function replacementNoticeState(ManagedEnvironment $e):array
{
    $state=[];foreach(['account_example','sosecurity_account_roots','sosecurity_account_records','sosecurity_outbox_roots','sosecurity_outbox_records'] as $table){$state[$table]=$e->observer->query('SELECT * FROM '.$table)->fetchAll(PDO::FETCH_ASSOC);}return $state;
}

function replacementNoticeTypes(ManagedEnvironment $e,SoSecurity\Account\FactorNotices $source,bool $current=true):array
{
    $q=$e->observer->query("SELECT record_id,payload FROM sosecurity_account_records WHERE kind='notice'");$types=[];
    foreach($q->fetchAll(PDO::FETCH_ASSOC) as $row){$body=json_decode($row['payload'],true);if(!is_array($body)||!isset($body['type'])){throw new RuntimeException('Owned notice record is invalid.');}$types[]=$body['type'];if($current&&$body['valid_until']>$e->clock->time){Check::same($body['type'],$source->notificationForDispatch($row['record_id'])->notice()->type());}}
    sort($types);return $types;
}
