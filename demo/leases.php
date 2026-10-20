<?php
declare(strict_types=1);
namespace SoSecurityDemo;
use SoSecurity\Concurrency\LeaseManager;
use SoSecurity\Concurrency\LeasePolicy;
use SoSecurity\Storage\SessionStore;

/** Visitor sandbox: no global task authority or cross-session lock is granted. */
final class LeaseSamples
{
    private $clock;
    private $manager;
    public function __construct() { $this->clock = new DemoClock('leases'); $this->manager = new LeaseManager(new SessionStore('demo-leases', $this->clock), new LeasePolicy(2, 15, 45), $this->clock); }
    private function owner(): string { return $_SESSION['demo_lease_owner'] ?? 'worker-a'; }
    public function run(string $action): array
    {
        $owner = $this->owner(); $token = $_SESSION['demo_lease_tokens'][$owner] ?? '';
        if ($action === 'prepare') { $_SESSION['demo_lease_epoch'] = $this->manager->initialize('demo', 'resource'); return ['valid'=>true,'message'=>'已显式初始化当前访客的测试账本，重复初始化保留原序号。']; }
        if ($action === 'switch_owner') { $_SESSION['demo_lease_owner'] = $owner === 'worker-a' ? 'worker-b' : 'worker-a'; return ['valid'=>true,'message'=>'已切换服务器定义的测试工作者，凭据保留在各自服务器状态。']; }
        if ($action === 'advance' || $action === 'absolute') { $this->clock->advance($action === 'advance' ? 16 : 46); return ['valid'=>true,'message'=>'仅当前访客的测试时钟前进，后续操作必须重新检查持有权。']; }
        if ($action === 'store_failure') {
            $fault = new class implements \SoSecurity\Storage\AtomicStore { public function transact(string $key, callable $callback) { throw new \SoSecurity\Storage\StorageException('Fixed demonstration outage.'); } };
            (new LeaseManager($fault))->acquire('demo','resource','test');
        }
        if ($action === 'remove') {
            $valid = $this->manager->remove('demo','resource',$_SESSION['demo_lease_epoch'] ?? str_repeat('0',32));
        } elseif ($action === 'acquire') {
            $lease = $this->manager->acquire('demo','resource',$owner); $valid = $lease !== null;
            if ($lease !== null) { $_SESSION['demo_lease_old_tokens'][$owner] = $token; $_SESSION['demo_lease_tokens'][$owner] = $lease->token(); }
        } elseif ($action === 'release' || $action === 'stale_release') {
            $valid = $this->manager->release('demo','resource',$owner,$action === 'release' ? $token : ($_SESSION['demo_lease_old_tokens'][$owner] ?? ''));
        } else {
            $lease = $action === 'renew' ? $this->manager->renew('demo','resource',$owner,$token) : $this->manager->verify('demo','resource',$owner,$token); $valid = $lease !== null;
            if ($action === 'step' && $valid) { $_SESSION['demo_lease_steps'] = ($_SESSION['demo_lease_steps'] ?? 0)+1; }
        }
        return ['valid'=>$valid,'message'=>$valid ? '测试操作完成，状态由真实租约组件复核。' : '测试操作被拒绝：当前凭据无效、已过期、名额已占用或账本未排空。'];
    }
    public function state(): array
    {
        $status = $this->manager->inspect('demo','resource'); $owner = $this->owner(); $lease = null;
        if ($status->initialized()) { $lease = $this->manager->verify('demo','resource',$owner,$_SESSION['demo_lease_tokens'][$owner] ?? ''); }
        return ['initialized'=>$status->initialized(),'owner'=>$owner,'active'=>$status->active(),'available'=>$status->available(),'sequence'=>$status->sequence(),'retry_after'=>$status->retryAfter(),
            'current_valid'=>$lease !== null,'expires_in'=>$lease === null ? 0 : max(0,$lease->expiresAt()-$this->clock->now()),'steps'=>$_SESSION['demo_lease_steps'] ?? 0,'storage'=>'visitor_session_only'];
    }
}
