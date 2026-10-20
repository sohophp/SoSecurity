<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\Policy as OutboxPolicy;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlTransaction;

/** Same-PDO MFA security notice source. The host must call publish from a trusted factor event callback. */
final class FactorNotices
{
    private $dependencies;
    public function __construct(PDO $connection,string $site,string $scope,string $epoch,HmacKeys $integrityKeys,HmacKeys $outboxKeys,Repository $accounts,Notifications $notifications,callable $managementGuard,callable $publishGuard,callable $deliveryGuard,?Policy $policy=null,?Clock $clock=null)
    {
        foreach([$site,$scope] as $label){Guard::label($label);if(preg_match('//u',$label)!==1){throw new ConfigurationException('Use bounded UTF-8 factor notice labels.','configuration.factor_notices');}}
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)||$accounts->connection()!==$connection){throw new ConfigurationException('Use the exact account connection and epoch.','configuration.factor_notices');}
        $policy=$policy??new Policy();$clock=$clock??new \SoSecurity\Support\SystemClock();$unit=new SqlTransaction($connection,$clock,$policy->ioMilliseconds());$notifications->validateConfiguration($clock,$policy->allowsSmtpUtf8());
        $ledger=new Ledger($unit,'account-factor-notices:'.hash('sha256',$site),$scope,$epoch,$integrityKeys,$policy);
        $age=$policy->lifetime('factor_management_completed');$queuePolicy=new OutboxPolicy(['message_age'=>$age,'recovery_age'=>$age,'maximum_entries'=>$policy->maximumEntries(),'maximum_payload_bytes'=>64,'io_milliseconds'=>$policy->ioMilliseconds()]);
        $enqueue=static function(string $action,string $phase,string $s,string $producer,string $actor,array $metadata)use($scope,$publishGuard):bool{return $action==='enqueue'&&$s===$scope&&$producer==='account-factor-notice'&&$actor==='account-system'&&$publishGuard('enqueue',$phase,$scope,$metadata)===true;};
        $manage=static function(string $action,string $phase,string $s,string $producer,string $actor,array $metadata)use($scope,$managementGuard):bool{return $action==='initialize'&&$s===$scope&&$producer==='account-factor-notice'&&$actor==='account-system'&&$managementGuard('outbox.initialize',$phase,$scope,$metadata)===true;};
        $queue=new SqlOutbox($connection,$site,$epoch,$outboxKeys,$enqueue,$queuePolicy,$clock,$manage);
        $this->dependencies=static function()use($connection,$site,$scope,$epoch,$outboxKeys,$accounts,$notifications,$managementGuard,$publishGuard,$deliveryGuard,$policy,$clock,$unit,$ledger,$queue,$queuePolicy):array{return [$connection,$site,$scope,$epoch,$outboxKeys,$accounts,$notifications,$managementGuard,$publishGuard,$deliveryGuard,$policy,$clock,$unit,$ledger,$queue,$queuePolicy];};
    }
    private function d():array {return ($this->dependencies)();}
    private function authorize(SqlTransaction $unit,callable $guard,string $action,string $phase,string $scope,?AccountRecord $record=null):void
    {
        if($unit->invoke($guard,[$action,$phase,$scope,$record],'account.factor_notice_authority')!==true){throw new SecurityException('Current factor notification authority required.','account.factor_notice_denied');}
    }
    private static function id(string $id):void {if(!preg_match('/\A[a-f0-9]{64}\z/D',$id)){throw new ValidationException('Use exact factor notification identifiers.','account.factor_notice');}}
    private static function type(string $type):void {if(strpos($type,'factor_')!==0||!Notice::supports($type)){throw new ValidationException('Use a fixed MFA security event.','account.factor_notice');}}
    private function data(array $row):array
    {
        $d=$this->d();$body=json_decode($row['payload'],true,4);$fields=['format','type','subject','operation','issued_at','valid_until','envelope'];
        if(!is_array($body)||array_keys($body)!==$fields||$body['format']!==1||!is_string($body['type'])||!is_string($body['subject'])||!is_string($body['operation'])||!is_int($body['issued_at'])||!is_int($body['valid_until'])||!is_string($body['envelope'])||json_encode($body,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES)!==$row['payload']){throw new StorageException('MFA notification record changed.','account.factor_notice_corrupt');}
        self::type($body['type']);self::id($body['operation']);Guard::label($body['subject']);
        if(preg_match('//u',$body['subject'])!==1||$row['kind']!=='notice'||$row['owner']!==hash('sha256',$body['subject'])||$row['retire_at']!==$body['valid_until']||$row['record_id']!==hash('sha256',json_encode(['SoSecurity.Account.FactorNotice.1',$d[2],$body['type'],$body['subject'],$body['operation']],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES))){throw new StorageException('MFA notification binding changed.','account.factor_notice_corrupt');}
        return $body;
    }
    public function initialize():void
    {
        $d=$this->d();$d[14]->initialize($d[2],'account-factor-notice','account-system');$d[12]->run(function()use($d):void{$this->authorize($d[12],$d[7],'initialize','before',$d[2]);$d[13]->initialize();},null,function()use($d):void{$this->authorize($d[12],$d[7],'initialize','commit',$d[2]);});
    }
    /** Must run inside the same host PDO transaction as the factor event. A returned ID is provisional until host COMMIT. */
    public function publish(string $type,string $subject,string $operation):string
    {
        self::type($type);Guard::label($subject);if(preg_match('//u',$subject)!==1){throw new ValidationException('Use a bounded account subject.','account.factor_notice');}self::id($operation);$d=$this->d();$id=hash('sha256',json_encode(['SoSecurity.Account.FactorNotice.1',$d[2],$type,$subject,$operation],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        return $d[12]->enlist(function()use($d,$type,$subject,$operation,$id):string{
            $this->authorize($d[12],$d[8],'publish','before',$d[2]);$record=$d[12]->invoke([$d[5],'find'],[$d[2],$subject],'account.repository');
            if(!$record instanceof AccountRecord||$record->account()->scope()!==$d[2]||$record->account()->subject()!==$subject||$record->status()!=='active'||!$record->verified()){throw new SecurityException('Current verified account required for MFA notice.','account.factor_notice_denied');}
            $this->authorize($d[12],$d[8],'publish','account',$d[2],$record);$now=$d[12]->now();$until=$now+$d[10]->lifetime($type);$notice=new Notice($d[2],$id,$type,$record->address(),'',$now,$until);$envelope=$d[6]->seal($notice);
            if($d[13]->read($id)!==null){throw new SecurityException('MFA notification event was already recorded.','account.factor_notice_replayed');}$d[13]->capacity(1);
            $body=json_encode(['format'=>1,'type'=>$type,'subject'=>$subject,'operation'=>$operation,'issued_at'=>$now,'valid_until'=>$until,'envelope'=>$envelope],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
            $d[13]->put($id,hash('sha256',$subject),'notice',$body,$until);$d[14]->enqueue(new Message($d[2],'account-factor-notice',Message::identifier('account-notice-'.$id,$now),'mail','account.notice',$id,$id),'account-system');
            $this->authorize($d[12],$d[8],'publish','written',$d[2],$record);return $id;
        },null,function()use($d,$id):void{$this->authorize($d[12],$d[8],'publish','commit',$d[2]);if($d[13]->read($id)===null){throw new StorageException('MFA notice disappeared before host commit.','account.factor_notice_changed');}});
    }
    /** Private current read. Neither the notice ID nor a queue claim grants notification authority. */
    public function notificationForDispatch(string $id):?DispatchNotice
    {
        self::id($id);$d=$this->d();return $d[12]->run(function()use($d,$id):?DispatchNotice{
            $this->authorize($d[12],$d[9],'notification','before',$d[2]);$row=$d[13]->read($id);if($row===null){return null;}
            $body=$this->data($row);
            if($body['valid_until']<=$d[12]->now()){return null;}$record=$d[12]->invoke([$d[5],'find'],[$d[2],$body['subject']],'account.repository');if(!$record instanceof AccountRecord||$record->account()->scope()!==$d[2]||$record->account()->subject()!==$body['subject']||$record->status()!=='active'||!$record->verified()){return null;}
            $this->authorize($d[12],$d[9],'notification','read',$d[2],$record);$notice=$d[6]->open($body['envelope'],$d[2],$id,$body['type']);if($notice->issuedAt()!==$body['issued_at']||$notice->expiresAt()!==$body['valid_until']||!$notice->recipient()->equals($record->address())){return null;}
            $this->authorize($d[12],$d[9],'notification','commit',$d[2],$record);return new DispatchNotice($notice,'',$body['subject']);
        });
    }
    /** Explicit bounded cleanup of expired notices; Outbox has its own retention/maintenance lifecycle. */
    public function maintain(int $limit=20,string $after=''):array
    {
        $d=$this->d();return $d[12]->run(function()use($d,$limit,$after):array{
            $this->authorize($d[12],$d[7],'maintain','before',$d[2]);$rows=$d[13]->page($limit,$after);$remove=[];$next=$after;$now=$d[12]->now();
            foreach($rows as $row){if($row['kind']!=='notice'){throw new StorageException('Unexpected factor notice ledger record.','account.factor_notice_corrupt');}$next=$row['record_id'];if($row['retire_at']<=$now){$remove[$next]=$row['revision'];}}
            $removed=$remove?$d[13]->remove($remove):0;$this->authorize($d[12],$d[7],'maintain','commit',$d[2]);return ['removed'=>$removed,'next'=>$next,'done'=>count($rows)<$limit];
        });
    }
    /** Rewrap a bounded page without changing notice identity, recipient, expiry or Outbox body. */
    public function rotate(int $limit=20,string $after=''):array
    {
        $d=$this->d();return $d[12]->run(function()use($d,$limit,$after):array{
            $this->authorize($d[12],$d[7],'rotate','before',$d[2]);$rows=$d[13]->page($limit,$after);$root=$d[13]->rotateRoot();$resealed=0;$reencrypted=0;$next=$after;
            foreach($rows as $header){$next=$header['record_id'];$row=$d[13]->read($next);if($row===null||$row['revision']!==$header['revision']){throw new StorageException('MFA notification changed during rotation.','account.factor_notice_changed');}$body=$this->data($row);
                if($d[6]->metadata($body['envelope'],$d[2],$next,$body['type'])['key_id']!==$d[6]->currentId()){$body['envelope']=$d[6]->reencrypt($body['envelope'],$d[2],$next,$body['type']);++$reencrypted;}
                $payload=json_encode($body,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
                if($payload!==$row['payload']||$row['seal_key']!==$d[13]->currentKeyId()){$d[13]->put($next,$row['owner'],'notice',$payload,$row['retire_at'],$row['revision']);++$resealed;}
            }
            $checkpoint=$d[13]->checkpoint();return ['result'=>['resealed'=>$resealed,'reencrypted'=>$reencrypted,'root_rotated'=>$root,'next'=>$next,'done'=>count($rows)<$limit],'checkpoint'=>$checkpoint];
        },null,function(array $state)use($d):void{$this->authorize($d[12],$d[7],'rotate','commit',$d[2]);if($d[13]->checkpoint()!==$state['checkpoint']){throw new StorageException('MFA notification rotation changed before commit.','account.factor_notice_changed');}})['result'];
    }
    public function dispatcher(string $worker,SendBudgets $budgets,MailTemplates $templates,MailTransport $transport,callable $workerAuthority,int $budgetMilliseconds=10000,int $transportMilliseconds=3000):Dispatcher
    {
        Guard::label($worker);$d=$this->d();$scope=$d[2];$producer='account-factor-notice';$authority=static function(string $action,string $phase,string $s,string $p,string $actor,array $metadata)use($scope,$producer,$worker,$workerAuthority):bool{return $s===$scope&&$p===$producer&&$actor===$worker&&in_array($action,['claim','current_claim','acknowledge','fail'],true)&&$workerAuthority($action,$phase,$s,$p,$actor,$metadata)===true;};
        $queue=new SqlOutbox($d[0],$d[1],$d[3],$d[4],$authority,$d[15],$d[11]);return new Dispatcher($d[1],$scope,$worker,$queue,$this,$budgets,$templates,$transport,$d[11],$budgetMilliseconds,$transportMilliseconds);
    }
    public function __debugInfo():array {return ['account_factor_notices'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild MFA notification configuration.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload MFA notification authority.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('MFA notification configuration is immutable.','configuration.immutable');}
}
