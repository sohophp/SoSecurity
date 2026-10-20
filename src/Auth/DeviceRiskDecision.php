<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\ConfigurationException;

/** A bounded, explainable decision; never contains raw device or network evidence. */
final class DeviceRiskDecision
{
    private $action;
    private $reason;

    public function __construct(string $action, string $reason)
    {
        $allowed = [
            'allow' => ['none'],
            'step_up' => ['anomalous', 'changed', 'reauth_required'],
            'deny' => ['compromised'],
        ];
        if (!isset($allowed[$action]) || !in_array($reason, $allowed[$action], true)) {
            throw new ConfigurationException('Invalid trusted-device risk decision.', 'configuration.device_risk');
        }
        $this->action = $action;
        $this->reason = $reason;
    }

    public function action(): string { return $this->action; }
    public function reason(): string { return $this->reason; }
    public function __set(string $name, $value): void
    {
        throw new ConfigurationException('Risk decisions are immutable.', 'configuration.immutable');
    }
}
