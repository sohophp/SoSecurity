<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Crypto\Cipher;
use SoSecurity\Support\HmacKeys;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

$first=str_repeat('A',32);$second=str_repeat('B',32);$values=['first'=>&$first,'second'=>&$second];
$cipher=new Cipher('first',$values,'synthetic.key-export');$mac=new HmacKeys('first',$values);$first=str_repeat('C',32);$second=str_repeat('D',32);
$body="binary\0message\xff";$binding="tenant\0object";$encrypted=$cipher->encrypt($body,$binding);$expectedMac=hash_hmac('sha256',$body,str_repeat('A',32),true);Check::same($expectedMac,$mac->sign($body));Check::same(true,$mac->verify('first',$body,$expectedMac));Check::same(false,$mac->verify('missing',$body,$expectedMac));Check::same($body,$cipher->decrypt($encrypted,$binding));
$rotation=new Cipher('second',['first'=>str_repeat('A',32),'second'=>str_repeat('B',32)],'synthetic.key-export');$new=$rotation->reencrypt($encrypted,$binding);$retired=new Cipher('second',['second'=>str_repeat('B',32)],'synthetic.key-export');Check::same($body,$retired->decrypt($new,$binding));Check::throws(ValidationException::class,static function()use($retired,$encrypted,$binding):void{$retired->decrypt($encrypted,$binding);});
foreach([$cipher,$mac,$rotation,$retired] as $object){
    $export=var_export($object,true);$printed=print_r($object,true);ob_start();var_dump($object);$dump=ob_get_clean();
    foreach([str_repeat('A',32),str_repeat('B',32),str_repeat('C',32),str_repeat('D',32)] as $key){Check::same(false,strpos($export,$key)!==false);Check::same(false,strpos($printed,$key)!==false);Check::same(false,strpos($dump,$key)!==false);}
    Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});
}
// A reconstructed raw-string/callable entry must never become a callable execution sink.
$GLOBALS['key_export_trap_calls']=0;
function key_export_trap():string {++$GLOBALS['key_export_trap_calls'];return str_repeat('T',32);}
foreach([Cipher::class,HmacKeys::class] as $class){
    $reflection=new ReflectionClass($class);$object=$reflection->newInstanceWithoutConstructor();
    foreach(['keys'=>['first'=>'key_export_trap'],'current'=>'first'] as $name=>$value){$property=$reflection->getProperty($name);if(PHP_VERSION_ID<80100){$property->setAccessible(true);}$property->setValue($object,$value);}
    if($class===Cipher::class){foreach(['purpose'=>'synthetic.key-export','maximum'=>65536] as $name=>$value){$property=$reflection->getProperty($name);if(PHP_VERSION_ID<80100){$property->setAccessible(true);}$property->setValue($object,$value);}Check::throws(ConfigurationException::class,static function()use($object):void{$object->encrypt('message','binding');});}
    else{Check::throws(ConfigurationException::class,static function()use($object):void{$object->sign('message');});}
    Check::same(0,$GLOBALS['key_export_trap_calls']);
}
final class KeyExportSink
{
    private $secret='SYNTHETIC-SINK-SECRET';
    public $records=[];
    public function write(array $record):void {$this->records[]=$record;}
}
$sink=new KeyExportSink();$audit=new SoSecurity\Audit\AuditLogger([$sink,'write'],str_repeat('P',32));
$export=var_export($audit,true);Check::same(false,strpos($export,str_repeat('P',32))!==false);Check::same(false,strpos($export,'SYNTHETIC-SINK-SECRET')!==false);Check::same('{}',json_encode($audit));
Check::throws(ConfigurationException::class,static function()use($audit):void{serialize($audit);});
$audit->record('account.changed','tenant','actor',['allowed'=>true,'retry_after'=>0,'status'=>201,'password'=>'SYNTHETIC-PRIVATE-INPUT']);Check::same(1,count($sink->records));$record=$sink->records[0];Check::same('account.changed',$record['event']);Check::same('tenant',$record['scope']);Check::same(hash_hmac('sha256','actor',str_repeat('P',32)),$record['subject']);Check::same(['allowed'=>true,'retry_after'=>0,'status'=>201],$record['context']);Check::same(false,strpos(json_encode($record),'SYNTHETIC-PRIVATE-INPUT')!==false);
$audit->record('account.changed','tenant');Check::same(null,$sink->records[1]['subject']);
echo 'PASS private key object exports: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; common exports redact keys, signatures/rotation retained, unsupported callable state refused\n";
