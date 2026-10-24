<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Support\SqlStateAccess;
use SoSecurity\Webhook\Endpoint;
use SoSecurity\Webhook\KeySet;
use SoSecurity\Webhook\ProcessingPolicy;

/** Exact complete receive/processing declaration. No provisioning or caller authorization. */
final class StateWebhookConnection
{
    private $dependencies;
    private $busy=false;
    private $admitting=false;
    public function __construct(StateBoundary $boundary,LocalStateWitness $witness,CompositeStateSnapshot $source,SqlStateSnapshot $sql,string $sqlName,WebhookStateSnapshot $configuration,string $configurationName,string $site,string $epoch,Endpoint $endpoint,KeySet $keys,HmacKeys $integrityKeys,?ProcessingPolicy $processing=null,?StateAccountConnection $accounts=null)
    {
        if(!$boundary->semanticAuthority()||!$boundary->boundTo($witness)||!$witness->matches($site,$endpoint->scope(),$epoch)||!$witness->coversSnapshot($source)||!$source->contains($sqlName,$sql)||!$source->contains($configurationName,$configuration)||$source->connection()!==$sql->connection()||$configuration->connection()!==$sql->connection()||!$configuration->uses($endpoint,$keys,$integrityKeys,$processing)){self::invalid();}
        $inbox=['endpoint_key'=>'digest','event_key'=>'digest','receipt_id'=>'bytes:32','event_id'=>'bytes:256','event_type'=>'bytes:128','resource_id'=>'bytes:256','descriptor'=>'digest','body_digest'=>'digest','payload'=>'blob:1048576','created_at'=>'int','seen_at'=>'int','source_key'=>'bytes:64','source_time'=>'nullable_int','seal_key'=>'bytes:64','seal'=>'digest'];
        if(!$sql->coversColumns('sosecurity_webhook_inbox',$inbox,['endpoint_key','event_key'],[])){self::invalid();}
        if($processing!==null){
            $columns=['endpoint_key'=>'digest','receipt_id'=>'bytes:32','event_key'=>'digest','body_digest'=>'digest','descriptor'=>'digest','policy'=>'digest','status'=>'bytes:16','attempt'=>'int','total_attempts'=>'int','manual_retries'=>'int','revision'=>'int','due_at'=>'int','lease_until'=>'int','claim_digest'=>'bytes:64','worker_digest'=>'bytes:64','error_code'=>'bytes:64','created_at'=>'int','updated_at'=>'int','seal_key'=>'bytes:64','seal'=>'digest'];
            if(!$sql->coversColumns('sosecurity_webhook_processing',$columns,['endpoint_key','receipt_id'],[])){self::invalid();}
        }
        $pdo=$sql->connection();
        if($accounts!==null){if(!$accounts->boundTo($boundary)||!$accounts->boundToWitness($witness)){self::invalid();}}
        else{SqlStateAccess::bind($pdo,SqlStateAccess::context($site,$endpoint->scope(),$epoch),hash('sha256','SoSecurity.StateWebhookConnection.1.'.json_encode([$source->fingerprint(),$sqlName,$configurationName,$endpoint->fingerprint(),$processing===null?null:$processing->fingerprint()])), $boundary->sqlGuard($pdo));}
        $provider=static function()use($keys):KeySet{return $keys;};$binding=hash('sha256','SoSecurity.StateWebhook.Native.1.'.$boundary->binding().$source->fingerprint().$configuration->fingerprint());$maximum=$sql->maximumRows('sosecurity_webhook_inbox');$processingMaximum=$processing===null?0:$sql->maximumRows('sosecurity_webhook_processing');
        $this->dependencies=static function()use($boundary,$pdo,$site,$endpoint,$keys,$integrityKeys,$processing,$provider,$binding,$maximum,$processingMaximum):array{return [$boundary,$pdo,$site,$endpoint,$keys,$integrityKeys,$processing,$provider,$binding,$maximum,$processingMaximum];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Declare exact complete Webhook SQL and local key configuration on the same state boundary.','configuration.state_webhook');}
    public function boundTo(StateBoundary $boundary):bool{return ($this->dependencies)()[0]===$boundary;}
    public function assertActive():void{($this->dependencies)()[0]->assertActive();}
    /** @internal Exact fixed provider identity for the native receive graph. */
    public function keyProvider():\Closure{return ($this->dependencies)()[7];}
    public function binding():string{return ($this->dependencies)()[8];}
    public function assertVerification():void{if(!$this->admitting){$this->assertActive();}}
    /** @internal Trusted read-only admission runs before pending; it cannot resume unknown results. */
    public function receive(callable $admission,callable $operation)
    {
        $d=($this->dependencies)();if($this->busy||$d[0]->active()){throw new ConfigurationException('Enter native Webhook receive directly once.','configuration.state_request_nested');}$this->busy=true;
        try{return $d[0]->run('webhook.receive',$operation,function(string $expected)use($admission){$this->admitting=true;try{return $admission($expected);}finally{$this->admitting=false;}});}
        finally{$this->busy=false;$this->admitting=false;}
    }
    /** @internal Native processing shares the same non-nesting context as receive. */
    public function process(string $operation,callable $admission,callable $effect)
    {
        $d=($this->dependencies)();if($d[6]===null||!in_array($operation,['claim','execute','fail','retry','status','pending'],true)){self::invalid();}
        if($this->busy||$d[0]->active()){throw new ConfigurationException('Enter native Webhook processing directly once.','configuration.state_request_nested');}$this->busy=true;
        try{return $d[0]->run('webhook.processing.'.$operation,$effect,$admission);}finally{$this->busy=false;}
    }
    public function processingLimit():int{return ($this->dependencies)()[10];}
    public function inboxLimit():int{return ($this->dependencies)()[9];}
    public function validateInbox(PDO $connection,string $site,\SoSecurity\Webhook\Verifier $verifier,HmacKeys $integrityKeys,\SoSecurity\Support\Clock $clock):void
    {
        $d=($this->dependencies)();$this->validateReceive($connection,$site,$verifier->endpoint(),$d[4],$integrityKeys);if(!$verifier->stateContext($d[3],$d[7],$clock)){self::invalid();}
    }
    public function validateVerifier(string $site,Endpoint $endpoint,KeySet $keys):void
    {
        $d=($this->dependencies)();if($d[2]!==$site||$d[3]->fingerprint()!==$endpoint->fingerprint()||$d[4]!==$keys){self::invalid();}
    }
    public function validateReceive(PDO $connection,string $site,Endpoint $endpoint,KeySet $keys,HmacKeys $integrityKeys):void
    {
        $this->validateVerifier($site,$endpoint,$keys);$d=($this->dependencies)();if($d[1]!==$connection||$d[5]!==$integrityKeys){self::invalid();}
    }
    public function validateProcessing(PDO $connection,string $site,Endpoint $endpoint,HmacKeys $integrityKeys,ProcessingPolicy $processing):void
    {
        $d=($this->dependencies)();if($d[1]!==$connection||$d[2]!==$site||$d[3]->fingerprint()!==$endpoint->fingerprint()||$d[5]!==$integrityKeys||$d[6]===null||$d[6]->fingerprint()!==$processing->fingerprint()){self::invalid();}
    }
    public function __clone(){throw new ConfigurationException('Do not clone active Webhook declarations.','configuration.state_webhook');}
    public function __debugInfo():array{return ['state_webhook_connection'=>'[redacted]'];}
    public function __sleep():array{throw new ConfigurationException('Rebuild Webhook state declarations.','configuration.state_webhook');}
    public function __wakeup():void{throw new ConfigurationException('Do not deserialize Webhook state declarations.','configuration.state_webhook');}
    public function __set(string $name,$value):void{throw new ConfigurationException('State declarations are immutable.','configuration.immutable');}
}
