<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/examples/request-budgets.php';

use SoSecurity\Auth\Account;
use SoSecurity\Auth\IdentityProvider;
use SoSecurity\Auth\SessionRegistry;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\Resource;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Csrf\CsrfTokens;
use SoSecurity\Security;
use SoSecurity\Storage\AtomicStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;

$directory=privateDirectory();
try {
    $clock=new TestClock();
    $actor=new Account('tenant','alice','v1',true,['editor']);
    $provider=new class($actor) implements IdentityProvider {
        public $account;
        public function __construct(Account $account) { $this->account=$account; }
        public function authenticate(string $scope,string $identifier,string $password): ?Account { return null; }
        public function find(string $scope,string $subject): ?Account {
            return $this->account->scope()===$scope && $this->account->subject()===$subject ? $this->account : null;
        }
    };
    $store=new FileStore($directory,'native-report', $clock);
    $sessions=new SessionRegistry($store,$provider,null,$clock);
    $epoch=$sessions->epoch('tenant','alice');
    $credential=$sessions->register('tenant','alice',hash('sha256',$actor->fingerprint().':none'),$epoch);
    Check::same(true,$credential!==null);
    $csrf=new CsrfTokens($store,300,4,$clock);
    $binding='host-session-binding';$token=$csrf->issue('reports:write',$binding);
    $authorizer=new Authorizer($provider,new RolePolicy([
        'report.export'=>['type'=>'report','roles'=>['editor'],'fields'=>[],'owner_attribute'=>'owner'],
    ]));
    $resource=new Resource('tenant','report','r1','v1',['owner'=>'alice']);
    $foreign=new Resource('tenant','report','r2','v1',['owner'=>'bob']);
    $config=['site'=>'native-report','storage'=>['driver'=>'file','directory'=>$directory],
        'budgets'=>['ip'=>['algorithm'=>'fixed_window','limit'=>20,'window'=>60],
            'account'=>['algorithm'=>'fixed_window','limit'=>3,'window'=>60],
            'tenant'=>['algorithm'=>'fixed_window','limit'=>20,'window'=>60]]];
    $security=Security::fromArray($config,[],$clock);
    $executed=0;$work=static function (Account $account,Resource $current) use (&$executed): string {
        ++$executed;Check::same('alice',$account->subject());Check::same('r1',$current->id());return 'business-result';
    };
    $loaded=0;
    $run=static function ($sessionToken,$csrfToken,Resource $target,Security $configured,string $method='POST',?callable $operation=null,?callable $resourceLoader=null) use ($sessions,$csrf,$authorizer,$binding,$work,&$loaded): array {
        $loader=$resourceLoader ?? static function () use ($target,&$loaded): Resource { ++$loaded; return $target; };
        return SoSecurity\Examples\runReportPost($configured,$sessions,$csrf,$authorizer,'tenant',$loader,$method,'alice',
            $sessionToken,$binding,$csrfToken,'report.export','192.0.2.1',$operation ?? $work);
    };
    Check::same(405,$run($credential->token(),$token,$resource,$security,'GET')['status']);
    Check::same(401,$run('bad',$token,$resource,$security)['status']);
    Check::same(403,$run($credential->token(),'bad',$resource,$security)['status']);
    Check::same(0,$loaded);
    Check::same(404,$run($credential->token(),$token,$resource,$security,'POST',null,static function () { return null; })['status']);
    Check::throws(SoSecurity\Exception\SecurityException::class,static function () use ($run,$credential,$token,$resource,$security): void {
        $run($credential->token(),$token,$resource,$security,'POST',null,static function () { return new Resource('other','report','r1','v1'); });
    });
    Check::same(403,$run($credential->token(),$token,$foreign,$security)['status']);
    Check::same(1,$loaded);Check::same(0,$executed);
    $accepted=$run($credential->token(),$token,$resource,$security);
    Check::same(200,$accepted['status']);Check::same('business-result',$accepted['value']);Check::same(1,$executed);
    $denied=$run($credential->token(),$token,$resource,$security);
    Check::same(429,$denied['status']);Check::same(true,$denied['retry_after']>0);Check::same(1,$executed);
    $failedConfig=$config;$failedConfig['site']='native-report-failed-work';
    $failedSecurity=Security::fromArray($failedConfig,[],$clock);
    Check::throws(RuntimeException::class,static function () use ($run,$credential,$token,$resource,$failedSecurity): void {
        $run($credential->token(),$token,$resource,$failedSecurity,'POST',static function (): void { throw new RuntimeException('local business failure'); });
    });
    Check::same(429,$run($credential->token(),$token,$resource,$failedSecurity)['status']);Check::same(1,$executed);
    $fault=new class implements AtomicStore {
        public function transact(string $key,callable $callback) { throw new StorageException('local simulated outage'); }
    };
    $faultConfig=$config;$faultConfig['storage']=['driver'=>'provided','connection'=>'fault'];
    $faultSecurity=Security::fromArray($faultConfig,['fault'=>$fault],$clock);
    Check::throws(StorageException::class,static function () use ($run,$credential,$token,$resource,$faultSecurity): void {
        $run($credential->token(),$token,$resource,$faultSecurity);
    });
    Check::same(1,$executed);
    $sessions->revoke('tenant','alice',$credential->id());
    Check::same(401,$run($credential->token(),$token,$resource,$security)['status']);Check::same(1,$executed);
    Check::same(PHP_SESSION_NONE,session_status());Check::same(false,headers_sent());
    echo 'PASS native report budget order: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; authentication, CSRF, authorization and budget reject before business\n";
} finally { cleanDirectory($directory); }
