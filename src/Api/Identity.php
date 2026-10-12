<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\Guard;

/** Authenticated credential identity; host still checks resource ownership and business permissions. */
final class Identity
{
    private $id;
    private $subject;
    private $scopes;
    public function __construct(string $id, string $subject, array $scopes)
    {
        Guard::label($id); Guard::label($subject);
        $this->id=$id; $this->subject=$subject; $this->scopes=self::validateScopes($scopes);
    }
    public static function validateScopes(array $scopes): array
    {
        if (count($scopes)>32) { throw new ConfigurationException('Too many credential scopes.'); }
        $copy=[];
        foreach ($scopes as $scope) {
            if (!is_string($scope) || !preg_match('/\A[a-z][a-z0-9:._-]{0,63}\z/D',$scope)) { throw new ConfigurationException('Invalid credential scope.'); }
            $copy[]=$scope;
        }
        return array_values(array_unique($copy));
    }
    public function id(): string { return $this->id; }
    public function subject(): string { return $this->subject; }
    public function scopes(): array { return $this->scopes; }
    public function allows(string $scope): bool { return in_array($scope,$this->scopes,true); }
    public function __set(string $name,$value): void { throw new ConfigurationException('Identity is immutable.','configuration.immutable'); }
}
