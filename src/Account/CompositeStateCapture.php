<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;

/** Internal selected bytes tied to the full composite digest; not an authorization capability. */
final class CompositeStateCapture
{
    private $contents;
    /** @internal Only a witness's own capture can be checked against its signed current digest. */
    public function __construct(CompositeStateSnapshot $source,string $digest,array $parts)
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$digest)||count($parts)<1||count($parts)>4){self::invalid();}$copy=[];
        foreach($parts as $name=>$part){if(!is_string($name)||strlen($name)>256||preg_match('//u',$name)!==1||(!$part instanceof SqlStateCapture&&!$part instanceof FileStateCapture)){self::invalid();}$copy[$name]=$part;}
        $fingerprint=$source->fingerprint();$this->contents=static function()use($source,$fingerprint,$digest,$copy):array{return [$source,$fingerprint,$digest,$copy];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use a bounded composite state capture.','configuration.state_capture');}
    public function matches(CompositeStateSnapshot $source):bool{$v=($this->contents)();return $v[0]===$source&&$v[1]===$source->fingerprint();}
    public function digest():string{return (($this->contents)())[2];}
    /** @return SqlStateCapture|FileStateCapture */
    public function part(string $name){$v=($this->contents)();if(!array_key_exists($name,$v[3])){self::invalid();}return $v[3][$name];}
    public function __debugInfo():array{return ['composite_state_capture'=>'[redacted]'];}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
