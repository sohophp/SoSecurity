<?php
declare(strict_types=1);
namespace SoSecurity\Operation;
use SoSecurity\Authorization\Resource;
use SoSecurity\Exception\ConfigurationException;

/** Server-loaded resource and validated business parameters; canonical binding is not business validation. */
final class Intent
{
    private $action;
    private $resource;
    private $parameters;
    private $fields;
    public function __construct(string $action,Resource $resource,array $parameters = [],array $fields = [])
    {
        \SoSecurity\Authorization\Shape::name($action); $this->action = $action; $this->resource = $resource;
        $this->parameters = Shape::parameters($parameters); $this->fields = \SoSecurity\Authorization\Shape::fields($fields); sort($this->fields);
    }
    public function action(): string { return $this->action; }
    public function resource(): Resource { return $this->resource; }
    public function parameters(): array { return $this->parameters; }
    public function fields(): array { return $this->fields; }
    public function fingerprint(): string { return hash('sha256',json_encode(['operation-v1',$this->action,$this->resource->fingerprint(),$this->parameters,$this->fields])); }
    public function __debugInfo(): array { return ['action'=>$this->action,'parameters'=>'[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Reload operation resources and parameters instead of serializing authority.','configuration.operation_serialization'); }
    public function __set(string $name,$value): void { throw new ConfigurationException('Operation intents are immutable.','configuration.immutable'); }
}
