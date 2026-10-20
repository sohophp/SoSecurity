<?php
declare(strict_types=1);
namespace SoSecurity\Idempotency;
use SoSecurity\Exception\ConfigurationException;

/** Result metadata is not permission to repeat business work. */
final class Outcome
{
    private $id;
    private $response;
    private $replayed;
    private $expires;
    public function __construct(string $executionId,Response $response,bool $replayed,int $expiresAt)
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$executionId)||$expiresAt<1){throw new ConfigurationException('Invalid execution metadata.','configuration.idempotency');}$this->id=$executionId;$this->response=$response;$this->replayed=$replayed;$this->expires=$expiresAt;
    }
    public function executionId():string {return $this->id;}
    public function response():Response {return $this->response;}
    public function replayed():bool {return $this->replayed;}
    public function expiresAt():int {return $this->expires;}
    public function __debugInfo():array {return ['execution_id'=>$this->id,'replayed'=>$this->replayed,'response'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize execution outcomes as authority.','configuration.idempotency_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Execution metadata is immutable.','configuration.immutable');}
}
