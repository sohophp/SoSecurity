<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Storage\StorageException;

/** @internal Small process-local cell retained by physical-store guards. */
final class StateExecutionContext
{
    private $entered = false;
    private $owner;
    private $operation;
    private $deadline;

    public function enter(?\SoSecurity\Support\Deadline $deadline=null): void { $this->owner = self::owner(); $this->operation = new \stdClass(); $this->deadline=$deadline; $this->entered = true; }
    public function leave(): void { $this->entered = false; $this->owner = null; $this->deadline=null; }
    public function entered(): bool { return $this->entered; }
    public function active(): bool { return $this->entered && $this->owner === self::owner(); }
    public function assertActive(): void
    {
        if (!$this->active()) {
            throw new StorageException('Protected physical storage requires its active operation authority.', 'account.state_required');
        }
    }
    /** Restriction only: an expired deadline must not block rollback or timeout restoration. */
    public function restrictDeadline(\SoSecurity\Support\Deadline $deadline):void
    {
        $this->assertActive();if($this->deadline!==null){$deadline->restrictTo($this->deadline);}
    }
    public function withinBudget(\SoSecurity\Support\Deadline $deadline,callable $operation)
    {
        $this->restrictDeadline($deadline);$deadline->check('account.operation_timeout');$previous=$this->deadline;$this->deadline=$deadline;
        try{$result=$operation();$deadline->check('account.operation_timeout');return $result;}finally{$this->deadline=$previous;}
    }
    public function refusalCheck(): \Closure
    {
        $before=$this->operation;$owner=self::owner();
        return function()use($before,$owner):bool{return !$this->entered&&$this->operation!==null&&$this->operation!==$before&&self::owner()===$owner;};
    }
    public function refusalScope(): \Closure
    {
        $this->assertActive();$operation=$this->operation;$owner=$this->owner;
        return function()use($operation,$owner):bool{return !$this->entered&&$this->operation===$operation&&self::owner()===$owner;};
    }
    private static function owner(): array
    {
        $pid = getmypid();
        if (!is_int($pid) || $pid < 1) { throw new StorageException('Cannot identify active execution context.', 'account.state_context'); }
        $fiber = PHP_VERSION_ID >= 80100 && class_exists('Fiber', false) ? \Fiber::getCurrent() : null;
        return [$pid, $fiber === null ? null : spl_object_id($fiber)];
    }
}
