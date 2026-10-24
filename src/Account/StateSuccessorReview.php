<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Operation\Intent;
use SoSecurity\Authorization\Resource;

/** Exact independent handoff selection. It authorizes staging isolation, never adoption or opening business work. */
final class StateSuccessorReview
{
    private $data;
    public function __construct(array $v){if(!self::valid($v)){self::invalid();}$v=json_decode(self::encode($v),true,4);$this->data=static function()use($v):array{return $v;};}
    public static function valid($v):bool
    {
        if(!is_array($v)||array_keys($v)!==['purpose','context','revision','predecessor','observed','intent','control','generation','issued','expires','nonce','key','seal']||$v['purpose']!=='stage_successor'||!is_int($v['revision'])||$v['revision']<1||$v['revision']>=PHP_INT_MAX-1||!is_int($v['issued'])||$v['issued']<1||!is_int($v['expires'])||$v['expires']<=$v['issued']||$v['expires']-$v['issued']>120||$v['expires']>PHP_INT_MAX-31536001||!is_string($v['key'])||!preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,31}\z/D',$v['key'])){return false;}
        foreach(['context','predecessor','observed','intent','control','generation','nonce','seal'] as $k){if(!is_string($v[$k])||!preg_match('/\A[a-f0-9]{64}\z/D',$v[$k])){return false;}}return true;
    }
    public static function encode(array $v):string{return json_encode($v,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);}
    public function metadata():array{return ($this->data)();}
    public function fingerprint():string{return hash('sha256','SoSecurity.Account.StateSuccessorReview.1.'.self::encode($this->metadata()));}
    public function intent(string $scope):Intent{$v=$this->metadata();foreach(['revision','issued','expires'] as $k){$v[$k]=(string)$v[$k];}return new Intent('state.successor.stage',new Resource($scope,'state_authority',$v['context'],$this->fingerprint()),$v,array_keys($v));}
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use an exact sealed successor selection.','configuration.state_successor');}
    public function __debugInfo():array{return ['state_successor_review'=>'[redacted]'];}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
