<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Api\ApiKeys;
use SoSecurity\Api\SigningKey;
use SoSecurity\Api\KeyRing;
use SoSecurity\Api\NonceStore;
use SoSecurity\Api\SignaturePolicy;
use SoSecurity\Api\SignatureProfile;
use SoSecurity\Api\HmacSigner;
use SoSecurity\Api\HmacVerifier;
use SoSecurity\Storage\MemoryStore;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\Change;
use SoSecurity\Storage\StorageException;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;
$clock=new TestClock(); $baseline=time()+300; $clock->time=$baseline; $directory=privateDirectory();
// Redis EXPIREAT uses server wall time; keep the controlled test clock near it, then advance logical expiry.
try {
    $stores=[new MemoryStore($clock),new FileStore($directory,'api-test',$clock)];
    if (getenv('SOSECURITY_TEST_REDIS_SOCKET')) {
        $redis=new Redis(); $redis->connect(getenv('SOSECURITY_TEST_REDIS_SOCKET'),0,2.0);
        $redisStore=new SoSecurity\Storage\RedisStore($redis,'api-test',$clock); $redisStore->initialize(); $stores[]=$redisStore;
    }
    if (getenv('SOSECURITY_TEST_MYSQL_SOCKET')) {
        $pdo=new PDO('mysql:unix_socket='.getenv('SOSECURITY_TEST_MYSQL_SOCKET').';dbname=sosecurity_test;charset=utf8mb4','sosecurity_test','integration-only',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
        $stores[]=new SoSecurity\Storage\MySqlStore($pdo,'api-test',$clock);
    }
    foreach ($stores as $store) {
        $keys=new ApiKeys($store,$clock); $credential=$keys->issue('client-1',['orders:read','orders:read'],10); $token=$credential->token(); $id=$credential->identity()->id();
        Check::same(102,strlen($token)); Check::same(['orders:read'],$credential->identity()->scopes());
        $stored=$store->transact('api-key:'.hash('sha256',$id),function ($record) { return new Change($record,$record['expires'],$record); });
        Check::same(hash('sha256',$token),$stored['digest']); Check::same(false,strpos(json_encode($stored),$token));
        Check::same('client-1',$keys->authenticate($token,'orders:read')->subject()); Check::same(null,$keys->authenticate($token,'orders:write'));
        Check::same($id,$keys->fromAuthorization('bearer '.$token)->id());
        foreach ([null,[],1,'',strtoupper($token),$token.'x','sosk_'.str_repeat('f',32).'.'.str_repeat('a',64)] as $bad) { Check::same(null,$keys->authenticate($bad)); }
        foreach ([$token,'Basic '.$token,"Bearer $token\r\n",'Bearer '.str_repeat('x',10000)] as $bad) { Check::same(null,$keys->fromAuthorization($bad)); }
        ob_start(); var_dump($credential); $debug=ob_get_clean(); Check::same(false,strpos($debug,$token));
        Check::same('{}',json_encode($credential));
        $replacement=$keys->rotate($id); Check::same(false,$replacement->token()===$token); Check::same($id,$replacement->identity()->id()); Check::same($credential->expiresAt(),$replacement->expiresAt());
        Check::same(null,$keys->authenticate($token)); Check::same($id,$keys->authenticate($replacement->token())->id());
        Check::same(true,$keys->revoke($id)); Check::same(false,$keys->revoke($id)); Check::same(null,$keys->authenticate($replacement->token())); Check::same(null,$keys->rotate($id));
        $expiring=$keys->issue('client-2',[],1); $clock->time++; Check::same(null,$keys->authenticate($expiring->token())); Check::same(null,$keys->rotate($expiring->identity()->id()));
        Check::throws(ConfigurationException::class,function () use ($keys) { $keys->issue('client',['*']); });
        Check::throws(ConfigurationException::class,function () use ($keys) { $keys->issue('client',[],0); });
        Check::throws(ValidationException::class,function () use ($keys) { $keys->revoke('invalid'); });
        $clock->time=$baseline;
        $key=SigningKey::generate('service-1',['orders:read']); $policy=new SignaturePolicy(['origin'=>'https://api.example.com']);
        $signer=new HmacSigner($policy,$key,$clock); $verifier=new HmacVerifier($policy,new KeyRing([$key]),new NonceStore($store,$clock),$clock);
        $url='https://api.example.com/orders?q=a%20b&x=1&x=2'; $body="{\"a\":1}"; $headers=$signer->sign('POST',$url,$body,'application/json',60);
        Check::same(null,$verifier->verify('GET',$url,$body,$headers));
        Check::same(null,$verifier->verify('POST',$url.'&z=1',$body,$headers));
        Check::same(null,$verifier->verify('POST','https://evil.example.com/orders',$body,$headers));
        Check::same(null,$verifier->verify('POST',$url,$body.' ',$headers));
        Check::same(null,$verifier->verify('POST',$url,$body,$headers,'orders:write'));
        $changed=$headers; $changed['Content-Type']='text/plain'; Check::same(null,$verifier->verify('POST',$url,$body,$changed));
        foreach (['Signature','Content-Digest','Content-Type','Signature-Input'] as $name) {
            $changed=$headers; unset($changed[$name]); Check::same(null,$verifier->verify('POST',$url,$body,$changed));
            $changed=$headers; $changed[strtolower($name)]=$changed[$name]; Check::same(null,$verifier->verify('POST',$url,$body,$changed));
            $changed=$headers; $changed[$name]=[$changed[$name]]; Check::same(null,$verifier->verify('POST',$url,$body,$changed));
            $changed=$headers; $changed[$name].="\r\nX: injected"; Check::same(null,$verifier->verify('POST',$url,$body,$changed));
        }
        foreach (['alg="hmac-sha256"'=>'alg="none"','tag="sosecurity-v1"'=>'tag="other"','"@method" '=>'',';expires='=>';created='.$baseline.';expires=','sig1='=>'sig2='] as $before=>$after) {
            $changed=$headers; $changed['Signature-Input']=str_replace($before,$after,$headers['Signature-Input']); Check::same(null,$verifier->verify('POST',$url,$body,$changed));
        }
        Check::same('service-1',$verifier->verify('POST',$url,$body,$headers,'orders:read')->subject()); Check::same(null,$verifier->verify('POST',$url,$body,$headers));
        $headers=$signer->sign('POST',$url,$body); $clock->time=($baseline+90);
        Check::same($key->identity()->id(),$verifier->verify('POST',$url,$body,$headers)->id()); Check::same(null,$verifier->verify('POST',$url,$body,$headers));
        $clock->time++; Check::same(null,$verifier->verify('POST',$url,$body,$headers));
        $clock->time=$baseline; $headers=$signer->sign('POST',$url,$body);
        $clock->time=($baseline-31); Check::same(null,$verifier->verify('POST',$url,$body,$headers));
        $clock->time=($baseline-30); Check::same($key->identity()->id(),$verifier->verify('POST',$url,$body,$headers)->id());
        $clock->time=$baseline; $headers=$signer->sign('POST',$url,$body);
        Check::same(null,(new HmacVerifier($policy,new KeyRing([]),new NonceStore($store,$clock),$clock))->verify('POST',$url,$body,$headers));
        $fault=new class implements SoSecurity\Storage\AtomicStore { public function transact(string $key,callable $callback) { throw new StorageException('offline'); } };
        Check::throws(StorageException::class,function () use ($fault,$clock) { (new ApiKeys($fault,$clock))->issue('client'); });
        Check::throws(StorageException::class,function () use ($fault,$clock,$token) { (new ApiKeys($fault,$clock))->authenticate($token); });
        Check::throws(StorageException::class,function () use ($fault,$clock,$policy,$key,$url,$body,$headers) { (new HmacVerifier($policy,new KeyRing([$key]),new NonceStore($fault,$clock),$clock))->verify('POST',$url,$body,$headers); });
        $bad=$headers; $bad['Signature']='sig1=:'.base64_encode(str_repeat('x',32)).':';
        Check::same(null,(new HmacVerifier($policy,new KeyRing([$key]),new NonceStore($fault,$clock),$clock))->verify('POST',$url,$body,$bad));
        $corrupt=new class implements SoSecurity\Storage\AtomicStore { public function transact(string $key,callable $callback) { return $callback(['v'=>1])->result(); } };
        Check::throws(StorageException::class,function () use ($corrupt,$clock,$token) { (new ApiKeys($corrupt,$clock))->authenticate($token); });
        Check::throws(StorageException::class,function () use ($corrupt,$clock,$baseline) { (new NonceStore($corrupt,$clock))->consume('id',str_repeat('a',16),($baseline+100)); });
        $nonces=new NonceStore($store,$clock); $nonce=rtrim(strtr(base64_encode(random_bytes(24)),'+/','-_'),'=');
        Check::same(false,$nonces->consume('x',$nonce,$baseline)); Check::same(false,$nonces->consume('x',$nonce,($baseline+3601)));
        Check::same(true,$nonces->consume('x',$nonce,($baseline+1))); Check::same(false,$nonces->consume('x',$nonce,($baseline+1)));
        Check::same(true,$nonces->consume('y',$nonce,($baseline+1))); $clock->time++; Check::same(true,$nonces->consume('x',$nonce,($baseline+2))); $clock->time=$baseline;
        echo 'PASS API credential/signature contract: '.get_class($store)."\n";
    }
    foreach ([[],['origin'=>'http://api.example.com'],['origin'=>'https://api.example.com/path'],['origin'=>'https://api.example.com','maximum_lifetime'=>901],['origin'=>'https://api.example.com','clock_skew'=>'30'],['origin'=>'https://api.example.com','maximum_body'=>null],['origin'=>'https://api.example.com','unknown'=>1]] as $bad) { Check::throws(ConfigurationException::class,function () use ($bad) { new SignaturePolicy($bad); }); }
    $policy=new SignaturePolicy(['origin'=>'https://api.example.com','maximum_body'=>4]); $key=new SigningKey('test-key',str_repeat('k',32),'client',['read']); $signer=new HmacSigner($policy,$key,$clock);
    foreach (['https://api.example.com:443/a','https://API.example.com/a','https://api.example.com/a/../b','https://api.example.com/a#x','https://api.example.com'] as $url) { Check::throws(ValidationException::class,function () use ($signer,$url) { $signer->sign('GET',$url); }); }
    Check::throws(ValidationException::class,function () use ($signer) { $signer->sign('GET','https://api.example.com/',str_repeat('a',5)); });
    Check::throws(ValidationException::class,function () use ($signer) { $signer->sign('GET','https://api.example.com/','','text/plain',301); });
    Check::throws(ConfigurationException::class,function () { new KeyRing([new SigningKey('k',str_repeat('x',32),'s'),new SigningKey('k',str_repeat('y',32),'s')]); });
    Check::throws(ConfigurationException::class,function () { new SigningKey('k',str_repeat('x',31),'s'); });
    $secret=base64_decode('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==',true);
    // Published RFC 9421 Appendix B.2.5 primitive vector (not our stricter whole-request profile).
    $base="\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@authority\": example.com\n\"content-type\": application/json\n\"@signature-params\": (\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"";
    Check::same('pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=',base64_encode(SoSecurity\Api\Hmac::sign($base,$secret)));
    $factory=SoSecurity\Security::fromArray(['site'=>'api-factory','storage'=>['driver'=>'file','directory'=>$directory],'api'=>['origin'=>'https://api.example.com','key_provider'=>'ring']],['ring'=>new KeyRing([$key])],$clock);
    $headers=$factory->hmacSigner($key)->sign('GET','https://api.example.com/'); Check::same('client',$factory->hmacVerifier()->verify('GET','https://api.example.com/','',$headers,'read')->subject());
    Check::same(null,$factory->hmacVerifier()->verify('GET','https://api.example.com/','',$headers));
    $credential=$factory->apiKeys()->issue('factory',['read']); Check::same('factory',$factory->apiKeys()->authenticate($credential->token())->subject());
    Check::same('manual',array_column($factory->diagnose(),null,'check')['api.key_provider']['status']);
    Check::same('manual',array_column($factory->diagnose(),null,'check')['api.request_boundary']['status']);
    $signingOnly=SoSecurity\Security::fromArray(['site'=>'client','api'=>['origin'=>'https://api.example.com']]);
    Check::same('not_configured',array_column($signingOnly->diagnose(),null,'check')['api.key_provider']['status']);
    foreach (['memory','session'] as $driver) { Check::throws(ConfigurationException::class,function () use ($driver) { SoSecurity\Security::fromArray(['site'=>'a','storage'=>['driver'=>$driver]])->apiKeys(); }); }
    Check::throws(ConfigurationException::class,function () use ($clock) {
        $wrapped=new SoSecurity\Storage\NamespacedStore(new MemoryStore($clock),'wrapped');
        SoSecurity\Security::fromArray(['site'=>'a','storage'=>['driver'=>'provided','connection'=>'store']],['store'=>$wrapped],$clock)->apiKeys();
    });
    Check::throws(ConfigurationException::class,function () { SoSecurity\Security::fromArray(['site'=>'a'])->hmacSigner(SigningKey::generate('client')); });
    Check::throws(ConfigurationException::class,function () use ($directory) { SoSecurity\Security::fromArray(['site'=>'a','storage'=>['driver'=>'file','directory'=>$directory],'api'=>['origin'=>'https://api.example.com','key_provider'=>'missing']])->hmacVerifier(); });
    $badProvider=new class implements SoSecurity\Api\KeyProvider {
        public function find(string $id): ?SigningKey { throw new RuntimeException('sensitive details'); }
    };
    Check::throws(SoSecurity\Exception\SecurityException::class,function () use ($policy,$badProvider,$directory,$clock,$headers) { (new HmacVerifier($policy,$badProvider,new NonceStore(new FileStore($directory,'bad-provider',$clock),$clock),$clock))->verify('GET','https://api.example.com/','',$headers); });
    $wrongProvider=new class implements SoSecurity\Api\KeyProvider { public function find(string $id): ?SigningKey { return new SigningKey('another-key',str_repeat('x',32),'client'); } };
    Check::throws(SoSecurity\Exception\SecurityException::class,function () use ($policy,$wrongProvider,$directory,$clock,$headers) { (new HmacVerifier($policy,$wrongProvider,new NonceStore(new FileStore($directory,'wrong-provider',$clock),$clock),$clock))->verify('GET','https://api.example.com/','',$headers); });
    $bad=$headers; $bad['Signature-Input']=str_replace('nonce="','nonce="!', $bad['Signature-Input']);
    Check::same(null,$factory->hmacVerifier()->verify('GET','https://api.example.com/','',$bad));
    $bad=$headers; $bad['Signature-Input']=str_repeat('a',4097); Check::same(null,$factory->hmacVerifier()->verify('GET','https://api.example.com/','',$bad));
    foreach (['before','after'] as $phase) {
        $clock->time=$baseline;
        $inner=new MemoryStore($clock); $raceKeys=new ApiKeys($inner,$clock); $raceCredential=$raceKeys->issue('race-client',[],60);
        $clockStore=new class($clock,$phase,$inner) implements SoSecurity\Storage\AtomicStore {
            private $clock; private $inner; private $phase;
            public function __construct(TestClock $clock,string $phase,SoSecurity\Storage\AtomicStore $inner) { $this->clock=$clock; $this->inner=$inner; $this->phase=$phase; }
            public function transact(string $key,callable $callback) {
                if ($this->phase==='before') { $this->clock->time+=61; }
                $result=$this->inner->transact($key,$callback);
                if ($this->phase==='after') { $this->clock->time+=61; }
                return $result;
            }
        };
        $strictPolicy=new SignaturePolicy(['origin'=>'https://api.example.com','clock_skew'=>0]);
        $raceHeaders=(new HmacSigner($strictPolicy,$key,$clock))->sign('POST','https://api.example.com/task','{}');
        $raceVerifier=new HmacVerifier($strictPolicy,new KeyRing([$key]),new NonceStore($clockStore,$clock),$clock);
        Check::same(null,$raceVerifier->verify('POST','https://api.example.com/task','{}',$raceHeaders));
        $clock->time=$baseline;
        Check::same(null,(new ApiKeys($clockStore,$clock))->authenticate($raceCredential->token()));
    }
    $clock->time=PHP_INT_MAX; Check::throws(ConfigurationException::class,function () use ($clock) { (new ApiKeys(new MemoryStore($clock),$clock))->issue('client'); });
    Check::throws(ConfigurationException::class,function () use ($clock,$policy,$key) { (new HmacSigner($policy,$key,$clock))->sign('GET','https://api.example.com/'); });
    echo 'PHP '.PHP_VERSION.': '.Check::$assertions." API credential/signature assertions passed\n";
} finally { cleanDirectory($directory); }
