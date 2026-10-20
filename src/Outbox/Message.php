<?php
declare(strict_types=1);
namespace SoSecurity\Outbox;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Support\Guard;

/** Server-built event description, never authentication. IDs bind immutable business-event creation time. */
final class Message
{
    private $scope;
    private $producer;
    private $id;
    private $created;
    private $destination;
    private $topic;
    private $aggregate;
    private $body;
    private $fingerprint;
    public function __construct(string $scope,string $producer,string $id,string $destination,string $topic,string $aggregate,string $body)
    {
        State::group($scope,$producer);$created=State::idTime($id);
        foreach([$destination,$topic] as $label){if(!preg_match('/\A[a-z][a-z0-9_.:-]{0,63}\z/D',$label)){throw new ValidationException('Use fixed destination and topic identifiers.','outbox.message');}}
        Guard::label($aggregate);if(!preg_match('//u',$aggregate)||strlen($body)>1048576){throw new ValidationException('Use bounded outbox aggregate and payload bytes.','outbox.message');}
        $this->scope=$scope;$this->producer=$producer;$this->id=$id;$this->created=$created;$this->destination=$destination;$this->topic=$topic;$this->aggregate=$aggregate;$this->body=static function()use($body):string{return $body;};
        $this->fingerprint=State::fingerprint($scope,$producer,$id,$destination,$topic,$aggregate,strlen($body),hash('sha256',$body));
    }
    /** Derive once from an immutable business-event reference/time; never substitute the dispatch/retry time. */
    public static function identifier(string $businessEvent,int $createdAt):string
    {
        Guard::label($businessEvent);if(!preg_match('//u',$businessEvent)||$createdAt<0||$createdAt>PHP_INT_MAX-31536001){throw new ValidationException('Use a stable business-event reference and creation time.','outbox.message');}
        return 'o1.'.$createdAt.'.'.hash('sha256','SoSecurity.Outbox.BusinessEvent.1.'.$businessEvent);
    }
    public function scope():string {return $this->scope;}
    public function producer():string {return $this->producer;}
    public function id():string {return $this->id;}
    public function createdAt():int {return $this->created;}
    public function destination():string {return $this->destination;}
    public function topic():string {return $this->topic;}
    public function aggregate():string {return $this->aggregate;}
    public function body():string {return ($this->body)();}
    public function fingerprint():string {return $this->fingerprint;}
    public function __debugInfo():array {return ['outbox_message'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild messages from trusted business data.','configuration.outbox_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload trusted Outbox data; do not deserialize capabilities.','configuration.outbox_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Outbox messages are immutable.','configuration.immutable');}
}
