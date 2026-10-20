<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;

/** Immutable bounded data from one full SQL digest, never authorization or a caller-supplied proof. */
final class SqlStateCapture
{
    private $contents;
    private static function name($value):bool{return is_string($value)&&preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D',$value)===1;}
    private static function record(array $row,int &$size,int $maximumColumns=16):array
    {
        if(count($row)<1||count($row)>$maximumColumns){self::invalid();}$copy=[];$bytes=0;
        foreach($row as $column=>$value){if(!self::name($column)||(!is_string($value)&&!is_int($value)&&$value!==null)){self::invalid();}$n=is_string($value)?strlen($value):(is_int($value)?19:0);$bytes+=$n;$size+=$n;if($bytes>65536||$size>262144){self::invalid();}$copy[$column]=$value;}return $copy;
    }
    /** @internal Only a witness's own capture can be evaluated against its sealed authority. */
    public function __construct(SqlStateSnapshot $source,string $digest,array $rows,array $pages=[])
    {
        if(!preg_match('/\A[a-f0-9]{64}\z/D',$digest)||count($rows)+count($pages)<1||count($rows)+count($pages)>8){self::invalid();}$copy=[];$pageCopy=[];$size=0;
        foreach($rows as $alias=>$row){if(!self::name($alias)){self::invalid();}if($row===null){$copy[$alias]=null;continue;}if(!is_array($row)){self::invalid();}$copy[$alias]=self::record($row,$size);}
        foreach($pages as $alias=>$page){
            if(!self::name($alias)||array_key_exists($alias,$copy)||!is_array($page)||array_keys($page)!==['rows','total','limit','more','cursor']||!is_array($page['rows'])||array_keys($page['rows'])!==(count($page['rows'])?range(0,count($page['rows'])-1):[])||!is_int($page['limit'])||$page['limit']<1||$page['limit']>8||count($page['rows'])>$page['limit']||!is_int($page['total'])||$page['total']<count($page['rows'])||$page['total']>1000000||!is_bool($page['more'])||($page['more']&&(count($page['rows'])!==$page['limit']||$page['total']<=count($page['rows'])))){self::invalid();}
            $records=[];foreach($page['rows'] as $row){if(!is_array($row)){self::invalid();}$records[]=self::record($row,$size);}$cursor=null;
            if($page['cursor']!==null){if(!is_array($page['cursor'])||$page['total']<1){self::invalid();}$cursor=self::record($page['cursor'],$size,4);foreach($cursor as $value){if($value===null||(is_int($value)&&$value<0)){self::invalid();}}}elseif($records!==[]){self::invalid();}
            $pageCopy[$alias]=['rows'=>$records,'total'=>$page['total'],'limit'=>$page['limit'],'more'=>$page['more'],'cursor'=>$cursor];
        }
        $fingerprint=$source->fingerprint();$this->contents=static function()use($source,$fingerprint,$digest,$copy,$pageCopy):array{return [$source,$fingerprint,$digest,$copy,$pageCopy];};
    }
    /** @return never */
    private static function invalid():void{throw new ConfigurationException('Use bounded exact SQL capture data.','configuration.state_capture');}
    public function matches(SqlStateSnapshot $source):bool{$v=($this->contents)();return $v[0]===$source&&$v[1]===$source->fingerprint();}
    public function digest():string{return (($this->contents)())[2];}
    public function same(SqlStateCapture $other):bool{return ($this->contents)()===($other->contents)();}
    public function row(string $alias):?array{$v=($this->contents)();if(!array_key_exists($alias,$v[3])){self::invalid();}return $v[3][$alias];}
    public function page(string $alias):array{$v=($this->contents)();if(!array_key_exists($alias,$v[4])){self::invalid();}return $v[4][$alias];}
    public function __debugInfo():array{return ['sql_state_capture'=>'[redacted]'];}
    public function __sleep():array{self::invalid();}
    public function __wakeup():void{self::invalid();}
    public function __set(string $name,$value):void{self::invalid();}
}
