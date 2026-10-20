<?php
declare(strict_types=1);
namespace SoSecurity\Auth;

use SoSecurity\Exception\ConfigurationException;

/** Server-owned modern password record. Credential/role changes must change Account::version(). */
final class PasswordRecord
{
    private $account;
    private $hash;
    public function __construct(Account $account, string $hash)
    {
        self::validateHash($hash); $this->account = $account;
        $this->hash = static function()use($hash):string{return $hash;};
    }
    public static function validateHash(string $hash): void
    {
        if (!\SoSecurity\Password\HashBudget::allows($hash)) { throw new ConfigurationException('Password hash exceeds the format/resource budget.', 'configuration.password_record'); }
        $info = password_get_info($hash); $options = $info['options'];
        if (($info['algoName'] === 'bcrypt' && isset($options['cost']) && $options['cost'] >= 4 && $options['cost'] <= 16)
            || (in_array($info['algoName'], ['argon2i', 'argon2id'], true) && isset($options['memory_cost'], $options['time_cost'], $options['threads'])
                && $options['memory_cost'] >= 1 && $options['memory_cost'] <= 262144 && $options['time_cost'] >= 1 && $options['time_cost'] <= 10
                && $options['threads'] >= 1 && $options['threads'] <= 4)) { return; }
        throw new ConfigurationException('Unknown or over-budget password hash profile.', 'configuration.password_record');
    }
    public function account(): Account { return $this->account; }
    /** Effective identity used by PasswordIdentityProvider; the raw account keeps its authoritative SQL version. */
    public function identity(): Account
    {
        $account=$this->account;
        $version=hash('sha256',json_encode([$account->version(),$this->hash()]));
        return new Account($account->scope(),$account->subject(),$version,$account->enabled(),$account->roles(),$account->mfaRequired());
    }
    public function hash(): string
    {
        if(!($this->hash instanceof \Closure)){throw new ConfigurationException('Reload password records from trusted account storage.','configuration.password_record');}
        return ($this->hash)();
    }
    public function __debugInfo(): array { return ['account' => $this->account, 'hash' => '[redacted]']; }
    public function __sleep(): array { throw new ConfigurationException('Do not serialize password records.', 'configuration.identity_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Reload password records from trusted account storage.', 'configuration.identity_serialization'); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Password records are immutable.', 'configuration.immutable'); }
}
