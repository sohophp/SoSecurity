<?php
declare(strict_types=1);
namespace SoSecurity\Account\Example;

use PDO;
use SoSecurity\Account\AccountRecord;
use SoSecurity\Account\Address;
use SoSecurity\Account\FactorMigrationRepository;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\PasswordRecord;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Support\SqlSchema;

/** Example host schema only. No implicit table creation, transaction control or password authentication. */
final class SqlAccounts implements FactorMigrationRepository
{
    private $read;
    public function __construct(PDO $connection) {$this->read=static function()use($connection):PDO{return $connection;};}
    public function connection():PDO {return ($this->read)();}
    private function query(string $sql,array $values=[]):\PDOStatement
    {
        $q=$this->connection()->prepare($sql);foreach($values as $name=>$value){$q->bindValue(':'.$name,$value,is_int($value)?PDO::PARAM_INT:($value===null?PDO::PARAM_NULL:PDO::PARAM_STR));}$q->execute();return $q;
    }
    private function select(string $where,array $values):?AccountRecord
    {
        $driver=$this->connection()->getAttribute(PDO::ATTR_DRIVER_NAME);$columns=SqlSchema::boundedProjection($driver,['scope'=>'bytes:256','subject'=>'bytes:256','credential_version'=>'bytes:256','address_version'=>'bytes:256','address'=>'bytes:254','status'=>'bytes:16','verified'=>'int','mfa_required'=>'int','roles'=>'bytes:4096']);
        $rows=$this->query('SELECT '.$columns.' FROM account_example WHERE '.$where.' LIMIT 2'.($driver==='mysql'?' FOR UPDATE':''),$values)->fetchAll(PDO::FETCH_ASSOC);
        if(!$rows){return null;}if(count($rows)!==1){throw new ConfigurationException('Host account uniqueness differs from its contract.','configuration.account_repository');}$row=$rows[0];
        foreach(['scope','subject','credential_version','address_version','address','status','roles'] as $key){if(!is_string($row[$key])){throw new ConfigurationException('Invalid bounded host account data.','configuration.account_repository');}}
        $verified=SqlSchema::integer($row['verified']);$mfa=SqlSchema::integer($row['mfa_required']);$roles=json_decode($row['roles'],true,3);
        if($verified>1||$mfa>1||!is_array($roles)||array_values($roles)!==$roles||json_encode($roles)!==$row['roles']){throw new ConfigurationException('Invalid host account flags/roles.','configuration.account_repository');}
        $address=new Address($row['address'],true);if($address->value()!==$row['address']){throw new ConfigurationException('Host must store the canonical address explicitly.','configuration.account_repository');}
        return new AccountRecord(new Account($row['scope'],$row['subject'],$row['credential_version'],$row['status']==='active',$roles,$mfa===1),$address,$row['address_version'],$verified===1,$row['status']);
    }
    public function find(string $scope,string $subject):?AccountRecord {return $this->select('scope=:scope AND subject=:subject',['scope'=>$scope,'subject'=>$subject]);}
    public function findAddress(string $scope,Address $address):?AccountRecord {return $this->select('scope=:scope AND address=:address',['scope'=>$scope,'address'=>$address->value()]);}
    public function passwordRecord(AccountRecord $expected):?PasswordRecord
    {
        $current=$this->find($expected->account()->scope(),$expected->account()->subject());if($current===null||$current->fingerprint()!==$expected->fingerprint()||$current->status()!=='active'||!$current->verified()){return null;}
        $driver=$this->connection()->getAttribute(PDO::ATTR_DRIVER_NAME);$columns=SqlSchema::boundedProjection($driver,['password'=>'bytes:4096']);
        $q=$this->query('SELECT '.$columns.' FROM account_example WHERE scope=:scope AND subject=:subject',['scope'=>$current->account()->scope(),'subject'=>$current->account()->subject()]);$hash=$q->fetchColumn();$q->closeCursor();
        if(!is_string($hash)){throw new ConfigurationException('Host password is missing or exceeds its read budget.','configuration.account_repository');}
        return new PasswordRecord($current->account(),$hash);
    }
    public function credentialBinding(AccountRecord $expected):?string
    {
        $r=$this->find($expected->account()->scope(),$expected->account()->subject());if($r===null||$r->fingerprint()!==$expected->fingerprint()){return null;}
        $columns=SqlSchema::boundedProjection($this->connection()->getAttribute(PDO::ATTR_DRIVER_NAME),['password'=>'bytes:4096']);
        $q=$this->query('SELECT '.$columns.',CASE WHEN password IS NULL THEN 1 ELSE 0 END AS password_absent FROM account_example WHERE scope=:scope AND subject=:subject',['scope'=>$r->account()->scope(),'subject'=>$r->account()->subject()]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();if($row===false){return null;}
        $missing=SqlSchema::integer($row['password_absent']);if($missing>1||($missing===1?$row['password']!==null:!is_string($row['password']))){throw new ConfigurationException('Host credentials exceed their read budget.','configuration.account_repository');}
        return hash('sha256',json_encode(['SoSecurity.Account.Example.CredentialBinding.1',$r->fingerprint(),$row['password']===null?null:hash('sha256',$row['password'])],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
    }
    public function migrationMaterialBinding(AccountRecord $expected):?string
    {
        $r=$this->find($expected->account()->scope(),$expected->account()->subject());if($r===null||$r->fingerprint()!==$expected->fingerprint()){return null;}
        $columns=SqlSchema::boundedProjection($this->connection()->getAttribute(PDO::ATTR_DRIVER_NAME),['password'=>'bytes:4096']);$q=$this->query('SELECT '.$columns.' FROM account_example WHERE scope=:scope AND subject=:subject',['scope'=>$r->account()->scope(),'subject'=>$r->account()->subject()]);$password=$q->fetchColumn();$q->closeCursor();if(!is_string($password)){throw new ConfigurationException('Migration requires bounded actual password material.','configuration.account_repository');}
        return hash('sha256',json_encode(['SoSecurity.Account.Example.MigrationMaterial.1',$r->account()->scope(),$r->account()->subject(),hash('sha256',$password),$r->address()->value(),$r->addressVersion(),$r->account()->roles(),$r->status(),$r->verified()]));
    }
    public function identity(AccountRecord $expected):?Account {$password=$this->passwordRecord($expected);return $password===null?null:$password->identity();}
    private static function duplicate(\PDOException $error):bool {if(!isset($error->errorInfo[1],$error->errorInfo[2])){return false;}return (int)$error->errorInfo[1]===1062||((int)$error->errorInfo[1]===19&&in_array($error->errorInfo[2],['UNIQUE constraint failed: account_example.scope, account_example.subject','UNIQUE constraint failed: account_example.scope, account_example.address'],true));}
    public function createPending(string $scope,string $subject,Address $address):?AccountRecord
    {
        try{$this->query("INSERT INTO account_example(scope,subject,credential_version,address_version,address,password,status,verified,mfa_required,roles) VALUES(:scope,:subject,:version,:address_version,:address,NULL,'pending',0,0,'[]')",['scope'=>$scope,'subject'=>$subject,'version'=>bin2hex(random_bytes(16)),'address_version'=>bin2hex(random_bytes(16)),'address'=>$address->value()])->closeCursor();}
        catch(\PDOException $error){if(self::duplicate($error)){return null;}throw $error;}
        return $this->find($scope,$subject);
    }
    private function mutate(AccountRecord $expected,string $assignment,array $values):?AccountRecord
    {
        $current=$this->find($expected->account()->scope(),$expected->account()->subject());if($current===null||$current->fingerprint()!==$expected->fingerprint()){return null;}
        $parameters=['scope'=>$expected->account()->scope(),'subject'=>$expected->account()->subject(),'expected_version'=>$expected->account()->version(),'expected_address_version'=>$expected->addressVersion(),'expected_address'=>$expected->address()->value(),'expected_status'=>$expected->status(),'expected_verified'=>$expected->verified()?1:0,'expected_mfa'=>$expected->account()->mfaRequired()?1:0,'expected_roles'=>json_encode($expected->account()->roles()),'next_version'=>bin2hex(random_bytes(16))]+$values;
        try{$q=$this->query('UPDATE account_example SET credential_version=:next_version,'.$assignment.' WHERE scope=:scope AND subject=:subject AND credential_version=:expected_version AND address_version=:expected_address_version AND address=:expected_address AND status=:expected_status AND verified=:expected_verified AND mfa_required=:expected_mfa AND roles=:expected_roles',$parameters);$changed=$q->rowCount()===1;$q->closeCursor();}
        catch(\PDOException $error){if(self::duplicate($error)){return null;}throw $error;}
        return $changed?$this->find($expected->account()->scope(),$expected->account()->subject()):null;
    }
    public function activate(AccountRecord $expected,string $passwordHash):?AccountRecord
    {
        PasswordRecord::validateHash($passwordHash);if($expected->status()!=='pending'||$expected->verified()){return null;}
        return $this->mutate($expected,"password=:password,status='active',verified=1",['password'=>$passwordHash]);
    }
    public function changeAddress(AccountRecord $expected,Address $address):?AccountRecord
    {
        if($expected->status()!=='active'||!$expected->verified()){return null;}
        return $this->mutate($expected,'address=:new_address,address_version=:new_address_version',['new_address'=>$address->value(),'new_address_version'=>bin2hex(random_bytes(16))]);
    }
    public function replacePassword(AccountRecord $expected,string $passwordHash):?AccountRecord
    {
        PasswordRecord::validateHash($passwordHash);if($expected->status()!=='active'||!$expected->verified()){return null;}
        return $this->mutate($expected,'password=:password',['password'=>$passwordHash]);
    }
    public function requireMfa(AccountRecord $expected):?AccountRecord
    {
        if($expected->status()!=='active'||!$expected->verified()){return null;}
        return $this->mutate($expected,'mfa_required=1',[]);
    }
    public function setMfa(AccountRecord $expected,bool $required):?AccountRecord
    {
        if($expected->status()!=='active'||!$expected->verified()){return null;}
        return $this->mutate($expected,'mfa_required=:required',['required'=>$required?1:0]);
    }
    public function __debugInfo():array {return ['example_account_repository'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload the private account connection.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload the private account connection.','configuration.account_serialization');}
}
