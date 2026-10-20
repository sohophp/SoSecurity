<?php
declare(strict_types=1);
require_once __DIR__.'/registration-support.php';

final class ChangeEnvironment
{
    public $e;
    public $service;
    public $provider;
    public $sessions;
    public $authentication;
    public $grants;
    public $credential;
    public $subject;
    public $onGuard;
    public $onBudget;
    public $onManager;
    public $onWorker;
    public $queueNamespace;
    public $password='owner-confirmation-password';
    public $reservations=[];
    public $factors;
    public $factorSecret;
    public function __construct(array $options=[],bool $mfa=false)
    {
        $this->e=new RegistrationEnvironment($options);$e=$this->e;$registration=$e->service();$registration->initialize();$registration->request('owner@example.com','setup');
        $delivery=$registration->notification($e->notices()[0]);if(!$registration->confirm($delivery->selector(),$delivery->notice()->token(),$this->password,'setup')){throw new RuntimeException('Owned test account activation failed.');}
        $e->pdo->exec("UPDATE account_example SET roles='[\"member\"]',credential_version='change-start-version'");$this->subject=$e->account()['subject'];
        $this->provider=new SoSecurity\Auth\PasswordIdentityProvider(
            static function(string $scope,string $identifier)use($e){$record=$e->accounts->findAddress($scope,new SoSecurity\Account\Address($identifier));return $record===null?null:$e->accounts->passwordRecord($record);},
            static function(string $scope,string $subject)use($e){$record=$e->accounts->find($scope,$subject);return $record===null?null:$e->accounts->passwordRecord($record);},
            $e->hasher,$e->account()['password']);
        $factor=null;
        if($mfa){
            $this->factors=new SoSecurity\Mfa\TotpFactors(new SoSecurity\Storage\MemoryStore($e->clock),new SoSecurity\Crypto\Cipher('factor',['factor'=>str_repeat('f',32)],'address-change-mfa',256),'Change test',$e->clock);
            $enrollment=$this->factors->begin('tenant',$this->subject,'owner@example.com');parse_str(parse_url($enrollment->provisioningUri(),PHP_URL_QUERY),$parts);$this->factorSecret=$parts['secret'];
            if($this->factors->confirm('tenant',$this->subject,$enrollment->id(),(new SoSecurity\Mfa\Totp())->codeAt($this->factorSecret,$e->clock->time))===null){throw new RuntimeException('Owned MFA setup failed.');}
            $e->pdo->exec("UPDATE account_example SET mfa_required=1,credential_version='change-mfa-version'");$factor=new SoSecurity\Auth\TotpSecondFactor($this->factors);
        }
        $this->sessions=new SoSecurity\Auth\SessionRegistry(new SoSecurity\Storage\MemoryStore($e->clock),$this->provider,$factor,$e->clock);
        $this->authentication=new SoSecurity\Auth\AuthenticationFlow(new SoSecurity\Storage\MemoryStore($e->clock),$this->provider,$this->sessions,static function():bool{return true;},$factor,$e->clock);
        $this->login();
        $rule=['type'=>'account','roles'=>['member'],'fields'=>['address'],'owner_attribute'=>'owner'];
        $authorizer=new SoSecurity\Authorization\Authorizer($this->provider,new SoSecurity\Authorization\RolePolicy(['account.address.request'=>$rule,'account.address.complete'=>$rule]));
        $this->grants=new SoSecurity\Operation\Grants(new SoSecurity\Storage\MemoryStore($e->clock),$this->sessions,$authorizer,static function():bool{return true;},new SoSecurity\Operation\Policy(120,8,300,1,['password','totp']),$e->clock);
        $this->service=$this->build();$this->service->initialize();$this->queueNamespace=SoSecurity\Outbox\State::namespace('account-test','tenant','account-address-change');
    }
    public function login(bool $replace=false):void
    {
        $result=$this->authentication->password('tenant','address-change-browser',$this->e->account()['address'],$this->password,'Change browser',$replace?$this->credential->token():null);
        if($result->status()==='mfa_required'){$this->e->clock->time=(intdiv($this->e->clock->time,30)+1)*30;$result=$this->authentication->secondFactor('tenant','address-change-browser',$result->challenge(),['type'=>'totp','code'=>(new SoSecurity\Mfa\Totp())->codeAt($this->factorSecret,$this->e->clock->time)]);}
        if($result->status()!=='authenticated'){throw new RuntimeException('Actual password authentication failed.');}$this->credential=$result->credential();
    }
    public function build(bool $management=true,bool $worker=true):SoSecurity\Account\AddressChange
    {
        $e=$this->e;
        $guard=function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record,?SoSecurity\Account\Address $address):bool{return $this->onGuard===null?true:($this->onGuard)($action,$phase,$scope,$record,$address);};
        $manager=function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record,?SoSecurity\Account\Address $address):bool{return $this->onManager===null?true:($this->onManager)($action,$phase,$scope,$record,$address);};
        $delivery=function(string $action,string $phase,string $scope,?SoSecurity\Account\AccountRecord $record,?SoSecurity\Account\Address $address):bool{return $this->onWorker===null?true:($this->onWorker)($action,$phase,$scope,$record,$address);};
        $budget=function(string $action,string $phase,string $scope,string $source,?SoSecurity\Account\Address $address,?string $subject)use($e):bool{
            if($this->onBudget!==null&&($this->onBudget)($action,$phase,$scope,$source,$address,$subject)!==true){return false;}
            $key=$action.':'.$source;
            if($phase==='public'){$bindings=['site'=>'all','source'=>hash('sha256',$source),'target'=>hash('sha256',$address===null?'confirmation':$address->value())];$decision=$e->limiter->consume('address-change-'.$scope,$bindings);$this->reservations[$key]=$decision->reservedUntil();return $decision->allowed();}
            if($phase==='subject'){$decision=$e->subjects->consume('address-change-subject-'.$scope,$subject);$this->reservations[$key]=min($this->reservations[$key],$decision->reservedUntil());return $decision->allowed();}
            return $phase==='final'&&isset($this->reservations[$key])&&$e->clock->time<$this->reservations[$key];
        };
        return new SoSecurity\Account\AddressChange($e->pdo,'account-test','tenant',str_repeat('e',64),new SoSecurity\Support\HmacKeys('account',['account'=>str_repeat('a',32)]),new SoSecurity\Support\HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$e->accounts,new SoSecurity\Account\Notifications('mail',['mail'=>str_repeat('m',32)],$e->clock),$this->sessions,$this->grants,$guard,$budget,$e->policy,$e->clock,$management?$manager:null,$worker?$delivery:null);
    }
    public function approve(SoSecurity\Operation\Intent $intent):string
    {
        $pending=$this->grants->begin('tenant',$this->subject,$this->credential->token(),$intent);++$this->e->clock->time;$this->login(true);
        $grant=$this->grants->confirm('tenant',$this->subject,$this->credential->token(),$intent,$pending->token());if($grant===null){throw new RuntimeException('Actual operation confirmation failed.');}return $grant->token();
    }
    public function request(string $address='new@example.com'):array
    {
        $intent=$this->service->proposal($this->subject,$address,$this->credential->token(),'ip');$grant=$this->approve($intent);$this->service->request($this->subject,$address,$this->credential->token(),$grant,'ip');return $this->deliveries();
    }
    public function deliveries():array
    {
        $q=$this->e->pdo->prepare('SELECT payload_body FROM sosecurity_outbox_records WHERE namespace=:namespace ORDER BY order_no');$q->execute(['namespace'=>$this->queueNamespace]);$ids=$q->fetchAll(PDO::FETCH_COLUMN);$result=[];
        foreach($ids as $id){$delivery=$this->service->notification($id);if($delivery!==null){$result[$delivery->notice()->type()]=$delivery;}}return $result;
    }
    public function flow(string $selector):array {$q=$this->e->pdo->prepare('SELECT payload FROM sosecurity_account_records WHERE record_id=:id');$q->execute(['id'=>$selector]);return json_decode($q->fetchColumn(),true);}
    public function count():int {$q=$this->e->pdo->prepare('SELECT COUNT(*) FROM sosecurity_outbox_records WHERE namespace=:namespace');$q->execute(['namespace'=>$this->queueNamespace]);return (int)$q->fetchColumn();}
    public function ready():array
    {
        $d=$this->request();foreach(['old','new'] as $side){$delivery=$d['verify_address_'.$side];if(!$this->service->confirm($delivery->selector(),$side,$delivery->notice()->token(),'ip')){throw new RuntimeException('Mailbox proof failed.');}}return $d;
    }
    public function close():void {$this->onGuard=null;$this->onBudget=null;$this->onManager=null;$this->onWorker=null;$this->service=null;$this->grants=null;$this->authentication=null;$this->sessions=null;$this->provider=null;$this->factors=null;$this->e->close();}
}
function changeCase(callable $test,array $options=[],bool $mfa=false):void {$e=new ChangeEnvironment($options,$mfa);try{$test($e);}finally{$e->close();}}
