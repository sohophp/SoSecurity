<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\ConfigurationException;

/** Classifies server-assessed signals; collecting and authenticating them is the host's responsibility. */
final class DeviceRiskPolicy
{
    public function decide(array $signals): DeviceRiskDecision
    {
        $expected = ['anomalous', 'changed', 'compromised', 'reauth_required'];
        $fields = array_keys($signals);
        sort($fields);
        if ($fields !== $expected) {
            throw new ConfigurationException('Provide every trusted-device risk signal.', 'configuration.device_risk');
        }
        foreach ($signals as $value) {
            if (!is_bool($value)) {
                throw new ConfigurationException('Risk signals must be server-assessed booleans.', 'configuration.device_risk');
            }
        }
        if ($signals['compromised']) { return new DeviceRiskDecision('deny', 'compromised'); }
        foreach (['anomalous', 'changed', 'reauth_required'] as $reason) {
            if ($signals[$reason]) { return new DeviceRiskDecision('step_up', $reason); }
        }
        return new DeviceRiskDecision('allow', 'none');
    }
}
