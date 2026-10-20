<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Server-loaded authorization metadata, not a client-supplied resource claim. */
final class Resource
{
    private $scope;
    private $type;
    private $id;
    private $version;
    private $attributes;
    public function __construct(string $scope, string $type, string $id, string $version, array $attributes = [])
    {
        Shape::name($type);
        foreach ([$scope, $id, $version] as $value) {
            Guard::label($value);
            if (!preg_match('//u', $value)) { throw new ConfigurationException('Resource labels must be UTF-8.', 'configuration.authorization'); }
        }
        $this->scope = $scope; $this->type = $type; $this->id = $id; $this->version = $version; $this->attributes = Shape::attributes($attributes);
    }
    public function scope(): string { return $this->scope; }
    public function type(): string { return $this->type; }
    public function id(): string { return $this->id; }
    public function version(): string { return $this->version; }
    public function attributes(): array { return $this->attributes; }
    public function fingerprint(): string { return hash('sha256', json_encode([$this->scope, $this->type, $this->id, $this->version, $this->attributes])); }
    public function __debugInfo(): array { return ['resource_type' => $this->type, 'metadata' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Reload resources instead of caching authorization snapshots.', 'configuration.authorization_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Resources are immutable.', 'configuration.immutable'); }
}
