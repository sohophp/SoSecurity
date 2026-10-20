<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

$body="Owned confidential upload content 49!\0\xff";
$path='/owned-private-uploads/11111111111111111111111111111111.txt';
$candidate=new SoSecurity\Upload\Candidate($body,'text/plain','txt',strlen($body));
$stored=new SoSecurity\Upload\StoredFile($path,$candidate,true);
Check::same($body,$candidate->contents());Check::same(strlen($body),$candidate->bytes());
Check::same(hash('sha256',$body),$candidate->digest());Check::same($path,$stored->path());
$metadata=$stored->metadata();Check::same(false,array_key_exists('path',$metadata));
Check::same(hash('sha256',$body),$metadata['sha256']);Check::same(true,$metadata['scanner_passed']);
foreach([$candidate,$stored] as $object){
    foreach([var_export($object,true),print_r($object,true),json_encode($object),var_export(['nested'=>$object],true),print_r(['nested'=>$object],true)] as $dump){
        Check::same(false,strpos($dump,'Owned confidential upload content')!==false);
        Check::same(false,strpos($dump,$path)!==false);
    }
    ob_start();var_dump($object);$dump=ob_get_clean();
    Check::same(false,strpos($dump,'Owned confidential upload content')!==false);Check::same(false,strpos($dump,$path)!==false);
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($object):void{serialize($object);});
    $class=get_class($object);$serialized='O:'.strlen($class).':"'.$class.'":0:{}';
    Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($serialized):void{unserialize($serialized);});
}
Check::same($body,(clone $candidate)->contents());Check::same($path,(clone $stored)->path());
Check::same($metadata,$stored->metadata());
echo 'PASS private upload exports: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; explicit accessors preserved, nested debug exports hide body/private path and serialization is refused\n";
