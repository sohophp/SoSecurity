<?php
declare(strict_types=1);
namespace SoSecurity\Outbox;
use SoSecurity\Exception\ConfigurationException;

/** Safe descriptive metadata only; constructing this object confers no queue permissions. */
final class Status
{
    private $values=[];
    public function __construct(array $values)
    {
        $fields=['id','delivery_id','order','state','destination','topic','aggregate','attempts','manual_retries','available_at','lease_until','deliver_until','sent_at','last_error'];
        if(count($values)!==count($fields)||array_diff(array_keys($values),$fields)){throw new ConfigurationException('Invalid outbox status shape.','configuration.outbox');}
        foreach(['order','attempts','manual_retries','available_at','lease_until','deliver_until','sent_at'] as $field){if(!is_int($values[$field])||$values[$field]<0){throw new ConfigurationException('Invalid outbox status number.','configuration.outbox');}}
        foreach(['id','delivery_id','state','destination','topic','aggregate','last_error'] as $field){if(!is_string($values[$field])||strlen($values[$field])>256){throw new ConfigurationException('Invalid outbox status value.','configuration.outbox');}}
        State::idTime($values['id']);if(!preg_match('/\A[a-f0-9]{64}\z/D',$values['delivery_id'])||!in_array($values['state'],['pending','leased','sent','dead','resolved'],true)){throw new ConfigurationException('Invalid outbox status identity.','configuration.outbox');}
        if($values['state']==='resolved'&&(!in_array($values['last_error'],['reconcile.received','reconcile.cancelled'],true)||$values['lease_until']!==0||$values['sent_at']!==0)){throw new ConfigurationException('Invalid outbox resolution status.','configuration.outbox');}
        if($values['order']<1||$values['order']>=PHP_INT_MAX||$values['attempts']>100||$values['manual_retries']>10){throw new ConfigurationException('Invalid outbox status bounds.','configuration.outbox');}
        foreach(['destination','topic'] as $field){if(!preg_match('/\A[a-z][a-z0-9_.:-]{0,63}\z/D',$values[$field])){throw new ConfigurationException('Invalid outbox destination/topic.','configuration.outbox');}}
        \SoSecurity\Support\Guard::label($values['aggregate']);if(!preg_match('//u',$values['aggregate'])||($values['last_error']!==''&&!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$values['last_error']))){throw new ConfigurationException('Invalid outbox status text.','configuration.outbox');}
        foreach($fields as $field){$this->values[$field]=$values[$field];}
    }
    public function id():string {return $this->values['id'];}
    public function deliveryId():string {return $this->values['delivery_id'];}
    public function order():int {return $this->values['order'];}
    public function state():string {return $this->values['state'];}
    public function attempts():int {return $this->values['attempts'];}
    public function manualRetries():int {return $this->values['manual_retries'];}
    public function availableAt():int {return $this->values['available_at'];}
    public function leaseUntil():int {return $this->values['lease_until'];}
    public function deliverUntil():int {return $this->values['deliver_until'];}
    public function sentAt():int {return $this->values['sent_at'];}
    public function resolution():?string {return $this->values['state']==='resolved'?substr($this->values['last_error'],10):null;}
    public function metadata():array {return $this->values;}
    public function __debugInfo():array {return ['outbox_status'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload current outbox status.','configuration.outbox_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Outbox status is immutable.','configuration.immutable');}
}
