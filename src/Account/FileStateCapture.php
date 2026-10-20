<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;

/** Internal copied bytes; a capture never grants permission or independent freshness. */
final class FileStateCapture
{
    private $contents;
    /** @internal Created by a concrete FileStateSnapshot. */
    public function __construct(FileStateSnapshot $source,string $digest,array $files)
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$digest)||count($files)<1||count($files)>4){self::invalid();}$copy=[];
        foreach($files as $alias=>$raw){if(!is_string($alias)||!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$alias)||($raw!==null&&(!is_string($raw)||strlen($raw)>65536))){self::invalid();}$copy[$alias]=$raw;}
        $fingerprint=$source->fingerprint();$this->contents=static function()use($source,$fingerprint,$digest,$copy):array{return [$source,$fingerprint,$digest,$copy];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use a bounded physical state capture.','configuration.state_capture');}
    public function matches(FileStateSnapshot $source):bool{$v=($this->contents)();return $v[0]===$source&&$v[1]===$source->fingerprint();}
    public function digest():string{return (($this->contents)())[2];}
    public function same(FileStateCapture $other):bool{return ($this->contents)()===($other->contents)();}
    public function file(string $alias):?string{$v=($this->contents)();if(!array_key_exists($alias,$v[3])){self::invalid();}return $v[3][$alias];}
    public function __debugInfo():array{return ['file_state_capture'=>'[redacted]'];}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
