<?php
declare(strict_types=1);
namespace SoSecurity\Authorization;
use SoSecurity\Exception\ConfigurationException;

/** A decision is not a reusable grant. Empty fields grant object access only, never every field. */
final class Decision
{
    private $allowed;
    private $fields;
    private $reason;
    public function __construct(bool $allowed, array $fields = [], string $reason = 'authorization.policy')
    {
        Shape::name($reason); $fields = Shape::fields($fields);
        if (!$allowed && $fields) { throw new ConfigurationException('Denied decisions cannot grant fields.', 'configuration.authorization'); }
        $this->allowed = $allowed; $this->fields = $fields; $this->reason = $reason;
    }
    public static function allow(array $fields = []): self { return new self(true, $fields, 'authorization.allowed'); }
    public static function deny(string $reason = 'authorization.denied'): self { return new self(false, [], $reason); }
    public function allowed(): bool { return $this->allowed; }
    public function fields(): array { return $this->fields; }
    public function reason(): string { return $this->reason; }
    public function __debugInfo(): array { return ['allowed' => $this->allowed, 'reason' => $this->reason, 'field_count' => count($this->fields)]; }
    public function __sleep(): array { throw new ConfigurationException('Do not cache authorization decisions as authority.', 'configuration.authorization_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Decisions are immutable.', 'configuration.immutable'); }
}
