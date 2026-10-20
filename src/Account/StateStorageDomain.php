<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use PDO;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\SqlTransaction;
use SoSecurity\Support\SystemClock;

/** Conservative physical isolation check, not a claim about an operator's backup tooling. */
final class StateStorageDomain
{
    public static function directory(string $path,array $stat):array{return ['kind'=>'file','identity'=>$stat['dev'].':'.$stat['ino'],'path'=>$path];}
    public static function sql(PDO $pdo,int $milliseconds):array
    {
        $u=new SqlTransaction($pdo,new SystemClock(),$milliseconds);
        return $u->run(static function()use($u):array{
            if($u->driver()==='mysql'){
                $q=$u->query('SELECT CASE WHEN OCTET_LENGTH(@@server_uuid)=36 THEN @@server_uuid ELSE NULL END AS server_id,CASE WHEN OCTET_LENGTH(DATABASE())<=64 THEN DATABASE() ELSE NULL END AS database_name');$v=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();
                if(!is_array($v)||!is_string($v['server_id'])||!preg_match('/\A[a-fA-F0-9-]{36}\z/D',$v['server_id'])||!is_string($v['database_name'])||$v['database_name']===''){self::invalid();}
                return ['kind'=>'sql','identity'=>hash('sha256',strtolower($v['server_id']).':'.strtolower($v['database_name'])),'path'=>null];
            }
            $q=$u->query('PRAGMA database_list');$path=null;$count=0;
            try{while($r=$q->fetch(PDO::FETCH_ASSOC)){if(++$count>16||!is_string($r['name'])||strlen($r['name'])>64||!is_string($r['file'])||strlen($r['file'])>4096){self::invalid();}if($r['name']==='main'){$path=$r['file'];}}}finally{$q->closeCursor();}
            if(!is_string($path)||$path===''||realpath($path)!==$path){self::invalid();}clearstatcache(true,$path);$s=@lstat($path);if(!is_array($s)||($s['mode']&0170000)!==0100000){self::invalid();}
            return ['kind'=>'sql','identity'=>'sqlite:'.$s['dev'].':'.$s['ino'],'path'=>$path];
        });
    }
    public static function disjoint(array $one,array $two):bool
    {
        if(!$one||!$two||count($one)>66||count($two)>66){return false;}
        foreach($one as $a){foreach($two as $b){
            if($a['kind']===$b['kind']&&$a['identity']===$b['identity']){return false;}
            if(is_string($a['path'])&&is_string($b['path'])&&($a['path']===$b['path']||($a['kind']==='file'&&strpos($b['path'],$a['path'].'/')===0)||($b['kind']==='file'&&strpos($a['path'],$b['path'].'/')===0))){return false;}
        }}return true;
    }
    /** @return never */
    private static function invalid():void{throw new StorageException('Cannot establish independent physical state domains.','account.state_domain');}
}
