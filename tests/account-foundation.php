<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';

use SoSecurity\Account\Address;
use SoSecurity\Account\Notice;
use SoSecurity\Account\Notifications;
use SoSecurity\Account\Policy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Storage\StorageException;

$address=new Address('User.Name+tag@EXAMPLE.COM');Check::same('User.Name+tag@example.com',$address->value());Check::same(false,$address->requiresSmtpUtf8());
Check::same(false,$address->equals(new Address('user.name+tag@example.com')));Check::same(false,$address->equals(new Address('UserName@example.com')));Check::same(false,$address->equals(new Address('User.Name@example.com')));
$maximum=str_repeat('a',64).'@'.str_repeat('b',63).'.'.str_repeat('c',63).'.'.str_repeat('d',61);Check::same(254,strlen((new Address($maximum))->value()));
foreach(['',"a\0@example.com","a@example.com\0","a@example.com\r\nBcc:x@example.com",' a@example.com','a @example.com','a@localhost','a@example.com.','a@[127.0.0.1]','a@[IPv6:::1]','a@a..example','a..b@example.com','"a"@example.com',"a\xff@example.com",str_repeat('a',65).'@example.com',$maximum.'d','a@'.str_repeat('x',64).'.com',str_repeat('x',1048577)] as $value){Check::throws(ValidationException::class,static function()use($value):void{new Address($value);});}
Check::throws(ValidationException::class,static function():void{new Address('用户@example.com');});
$internationalLocal=new Address('用户@example.com',true);Check::same('用户@example.com',$internationalLocal->value());Check::same(true,$internationalLocal->requiresSmtpUtf8());
Check::same(64,strlen(explode('@',(new Address(str_repeat('界',21).'a@example.com',true))->value())[0]));Check::throws(ValidationException::class,static function():void{new Address(str_repeat('界',22).'@example.com',true);});
$idna=function_exists('idn_to_ascii');
if($idna){
    Check::same('User@xn--fsqu00a.xn--0zwm56d',(new Address('User@例子.测试'))->value());
    Check::same('a@xn--fa-hia.de',(new Address('a@faß.de'))->value());
    Check::same(true,(new Address('a@faß.de'))->equals(new Address('a@XN--FA-HIA.DE')));
    Check::same('a@example.com',(new Address('a@ｅｘａｍｐｌｅ.com'))->value());
    foreach(['a@xn--a.com',"a@x\u{200d}.com"] as $value){Check::throws(ValidationException::class,static function()use($value):void{new Address($value);});}
}else{
    foreach(['a@例子.测试','a@xn--fa-hia.de'] as $value){Check::throws(DependencyException::class,static function()use($value):void{new Address($value);});}
}
$policy=new Policy();Check::same(86400,$policy->lifetime('verify_registration'));Check::same(1800,$policy->lifetime('verify_address_old'));Check::same(900,$policy->lifetime('recover_account'));Check::same(false,$policy->allowsSmtpUtf8());
$options=$policy->options();$options['maximum_attempts']=1;Check::same(5,$policy->maximumAttempts());Check::same((new Policy(array_reverse($policy->options(),true)))->fingerprint(),$policy->fingerprint());
$referenced=3;$configuration=['maximum_resends'=>&$referenced];$immutable=new Policy($configuration);$referenced=9;Check::same(3,$immutable->maximumResends());
foreach([['unknown'=>1],['maximum_attempts'=>'5'],['maximum_entries'=>0],['registration_seconds'=>604801],['resend_seconds'=>0],['smtp_utf8'=>1],['io_milliseconds'=>30001],['maximum_resends'=>11]] as $bad){Check::throws(ConfigurationException::class,static function()use($bad):void{new Policy($bad);});}
Check::throws(ConfigurationException::class,static function()use($policy):void{$policy->lifetime('arbitrary-template');});
$clock=new TestClock();$id=str_repeat('a',64);$token=str_repeat('1',64);$notice=new Notice('tenant',$id,'verify_registration',$address,$token,$clock->time,$clock->time+1800);
Check::same($notice->encode(),Notice::decode($notice->encode())->encode());Check::same($token,$notice->token());
foreach([
    ['tenant',$id,'arbitrary-template',$address,$token,100000,100001],
    ['tenant',$id,'verify_registration',$address,'',100000,100001],
    ['tenant',$id,'password_changed',$address,$token,100000,100001],
    ['tenant',$id,'verify_registration',$address,$token,100000,100000],
    ['tenant',$id,'verify_registration',$address,$token,100000,704801],
    ['tenant','not-id','verify_registration',$address,$token,100000,100001],
] as $bad){Check::throws(ValidationException::class,static function()use($bad):void{new Notice(...$bad);});}
foreach([$address,$policy,$notice] as $object){
    Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});
    Check::throws(ConfigurationException::class,static function()use($object):void{$object->injected='x';});
    $class=get_class($object);Check::throws(ConfigurationException::class,static function()use($class):void{unserialize('O:'.strlen($class).':"'.$class.'":0:{}');});
}
Check::same('{}',json_encode($notice));Check::same('{}',json_encode($address));ob_start();var_dump($notice,$address);$debug=ob_get_clean();Check::same(false,strpos($debug,$token)!==false);Check::same(false,strpos($debug,$address->value())!==false);
foreach([$notice,$address] as $object){$export=var_export($object,true);Check::same(false,strpos($export,$token)!==false);Check::same(false,strpos($export,$address->value())!==false);}
if(!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')){
    Check::throws(DependencyException::class,static function()use($clock):void{new Notifications('one',['one'=>str_repeat('a',32)],$clock);});
    echo 'PASS account foundation noncrypto: '.Check::$assertions.' assertions; IDNA='.($idna?'positive':'dependency refusal')." on PHP ".PHP_VERSION."\n";
    if(getenv('SOSECURITY_REQUIRE_CRYPTO')==='1'){throw new RuntimeException('Required sodium is absent.');}echo "NOT RUN encrypted account notification lifecycle: sodium unavailable\n";return;
}
$keys=['one'=>str_repeat('a',32)];$codec=new Notifications('one',$keys,$clock);$envelope=$codec->seal($notice);Check::same($notice->encode(),$codec->open($envelope,'tenant',$id,'verify_registration')->encode());Check::same(false,strpos($envelope,$address->value())!==false);Check::same(false,strpos($envelope,$token)!==false);
foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account','account_activated','password_changed','address_changed'] as $type){
    $secret=in_array($type,['account_activated','password_changed','address_changed'],true)?'':$token;
    $variant=new Notice('tenant',$id,$type,$address,$secret,$clock->time,$clock->time+$policy->lifetime($type));
    Check::same($variant->encode(),$codec->open($codec->seal($variant),'tenant',$id,$type)->encode());
}
$factorTypes=['factor_management_started','factor_management_completed','factor_management_abandoned','factor_enrollment_started','factor_enrollment_prepared','factor_enrolled','factor_enrollment_cancelled','factor_enrollment_cleaned','factor_management_cleaned','factor_privileged_revoked','factor_recovery_started','factor_replaced','factor_recovery_cancelled','factor_recovery_purged','factor_migration_reserved','factor_migration_completed','factor_migration_activated','factor_migration_cancelled','factor_migration_reapproved','factor_restoration_started','factor_restoration_activated','factor_restoration_cancelled','factor_restoration_cleaned','factor_restoration_previous_cleaned'];
foreach($factorTypes as $type){$variant=new Notice('tenant',$id,$type,$address,'',$clock->time,$clock->time+$policy->lifetime($type));Check::same($variant->encode(),$codec->open($codec->seal($variant),'tenant',$id,$type)->encode());Check::throws(ValidationException::class,static function()use($type,$address,$id,$token,$clock):void{new Notice('tenant',$id,$type,$address,$token,$clock->time,$clock->time+1);});}
foreach([['other',$id,'verify_registration'],['tenant',str_repeat('b',64),'verify_registration'],['tenant',$id,'recover_account']] as $context){Check::throws(ValidationException::class,static function()use($codec,$envelope,$context):void{$codec->open($envelope,...$context);});}
$damaged=$envelope;$offset=strlen($damaged)-9;$damaged[$offset]=$damaged[$offset]==='A'?'B':'A';
Check::throws(ValidationException::class,static function()use($codec,$damaged,$id):void{$codec->open($damaged,'tenant',$id,'verify_registration');});
Check::throws(ValidationException::class,static function()use($codec,$id):void{$codec->open(str_repeat('A',1048577),'tenant',$id,'verify_registration');});
$wrongPurpose=new SoSecurity\Crypto\Cipher('one',$keys,'different-purpose',4096);$binding='SoSecurity.Account.Notice.1.'.hash('sha256',json_encode(['tenant',$id,'verify_registration'],JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
Check::throws(ValidationException::class,static function()use($codec,$wrongPurpose,$binding,$notice,$id):void{$codec->open($wrongPurpose->encrypt($notice->encode(),$binding),'tenant',$id,'verify_registration');});
$rawCipher=new SoSecurity\Crypto\Cipher('one',$keys,'account.notifications',4096);$data=json_decode($notice->encode(),true);$extra=$data;$extra['url']='https://synthetic.invalid/';$wrongVersion=$data;$wrongVersion['format']=2;$wrongType=$data;$wrongType['issued_at']='100000';$wrongContext=$data;$wrongContext['scope']='another';$wrongRecipient=$data;$wrongRecipient['recipient']='User.Name+tag@EXAMPLE.COM';
$badJson=[json_encode($extra),json_encode($wrongVersion),json_encode($wrongType),json_encode($wrongContext),json_encode($wrongRecipient),' '.$notice->encode(),str_replace('"format":1','"format":1,"format":1',$notice->encode()),'{"format":1}'];
foreach($badJson as $encoded){Check::throws(ValidationException::class,static function()use($codec,$rawCipher,$binding,$encoded,$id):void{$codec->open($rawCipher->encrypt($encoded,$binding),'tenant',$id,'verify_registration');});}
foreach(['scope'=>"bad\0scope",'id'=>null,'recipient'=>['injected'],'smtp_utf8'=>'false','issued_at'=>100000.5,'expires_at'=>true] as $field=>$value){$bad=$data;$bad[$field]=$value;Check::throws(ValidationException::class,static function()use($bad):void{Notice::decode(json_encode($bad));});}
Check::throws(ValidationException::class,static function():void{Notice::decode(str_repeat('x',4097));});
$unicodeNotice=new Notice('tenant',$id,'recover_account',$internationalLocal,$token,$clock->time,$clock->time+900);
Check::throws(ConfigurationException::class,static function()use($codec,$unicodeNotice):void{$codec->seal($unicodeNotice);});
$unicodeCodec=new Notifications('one',$keys,$clock,true);$unicodeEnvelope=$unicodeCodec->seal($unicodeNotice);Check::same($unicodeNotice->encode(),$unicodeCodec->open($unicodeEnvelope,'tenant',$id,'recover_account')->encode());Check::throws(ConfigurationException::class,static function()use($codec,$unicodeEnvelope,$id):void{$codec->open($unicodeEnvelope,'tenant',$id,'recover_account');});
$rotated=new Notifications('two',['one'=>$keys['one'],'two'=>str_repeat('b',32)],$clock);$newEnvelope=$rotated->reencrypt($envelope,'tenant',$id,'verify_registration');$retired=new Notifications('two',['two'=>str_repeat('b',32)],$clock);Check::same($notice->encode(),$retired->open($newEnvelope,'tenant',$id,'verify_registration')->encode());Check::throws(ValidationException::class,static function()use($retired,$envelope,$id):void{$retired->open($envelope,'tenant',$id,'verify_registration');});
$clock->time=$notice->expiresAt();Check::throws(ValidationException::class,static function()use($retired,$newEnvelope,$id):void{$retired->open($newEnvelope,'tenant',$id,'verify_registration');});$stillExpired=$retired->reencrypt($newEnvelope,'tenant',$id,'verify_registration');Check::throws(ValidationException::class,static function()use($retired,$stillExpired,$id):void{$retired->open($stillExpired,'tenant',$id,'verify_registration');});
--$clock->time;Check::throws(StorageException::class,static function()use($retired,$newEnvelope,$id):void{$retired->open($newEnvelope,'tenant',$id,'verify_registration');});
$clock->time=100000;$boundaryClock=new class implements SoSecurity\Support\Clock {private $calls=0;public function now():int{return ++$this->calls===1?100000:101800;}};
Check::throws(ValidationException::class,static function()use($notice,$keys,$boundaryClock):void{(new Notifications('one',$keys,$boundaryClock))->seal($notice);});
$failedClock=new class implements SoSecurity\Support\Clock {public function now():int{throw new RuntimeException('SYNTHETIC-SECRET');}};
Check::throws(StorageException::class,static function()use($notice,$keys,$failedClock):void{(new Notifications('one',$keys,$failedClock))->seal($notice);});
foreach([$codec,$retired] as $object){Check::same('{}',json_encode($object));Check::throws(ConfigurationException::class,static function()use($object):void{serialize($object);});$class=get_class($object);Check::throws(ConfigurationException::class,static function()use($class):void{unserialize('O:'.strlen($class).':"'.$class.'":0:{}');});ob_start();var_dump($object);$dump=ob_get_clean();Check::same(false,strpos($dump,$keys['one'])!==false);}
foreach([$codec,$retired] as $object){$export=var_export($object,true);Check::same(false,strpos($export,str_repeat('a',32))!==false);Check::same(false,strpos($export,str_repeat('b',32))!==false);}
$privateClock=new class implements SoSecurity\Support\Clock {private $secret='SYNTHETIC-CLOCK-SECRET';public function now():int{return 100000;}};
Check::same(false,strpos(var_export(new Notifications('one',$keys,$privateClock),true),'SYNTHETIC-CLOCK-SECRET')!==false);

// Real local SQL consumer: same-PDO intent persistence and key rotation without rewriting Outbox's immutable body.
require __DIR__.'/outbox-support.php';
outboxCase(false,static function(OutboxEnvironment $e):void{
    $id=str_repeat('c',64);$token=str_repeat('d',64);$address=new Address('account+example@example.com');$notice=new Notice('tenant',$id,'verify_registration',$address,$token,$e->clock->time,$e->clock->time+1800);$old=new Notifications('one',['one'=>str_repeat('a',32)],$e->clock);$encrypted=$old->seal($notice);
    $s=$e->service();$s->initialize('tenant','accounts','admin');$e->pdo->exec('CREATE TABLE account_test_notices(id TEXT PRIMARY KEY,envelope TEXT NOT NULL)');
    $payload=json_encode(['notice'=>$id]);$message=new SoSecurity\Outbox\Message('tenant','accounts',SoSecurity\Outbox\Message::identifier('account-notice-'.$id,$e->clock->time),'mail','account.notice','subject-1',$payload);
    $e->pdo->exec('BEGIN IMMEDIATE');try{$q=$e->pdo->prepare('INSERT INTO account_test_notices VALUES(?,?)');$q->execute([$id,$encrypted]);$q->closeCursor();$s->enqueue($message,'alice');Check::same(0,(int)$e->observer->query('SELECT COUNT(*) FROM account_test_notices')->fetchColumn());$e->pdo->exec('COMMIT');}catch(Throwable $error){$e->pdo->exec('ROLLBACK');throw $error;}
    Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM account_test_notices')->fetchColumn());$rootBefore=$e->pdo->query('SELECT revision,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC);
    $new=new Notifications('two',['one'=>str_repeat('a',32),'two'=>str_repeat('b',32)],$e->clock);$reencrypted=$new->reencrypt($encrypted,'tenant',$id,'verify_registration');$q=$e->pdo->prepare('UPDATE account_test_notices SET envelope=? WHERE id=?');$q->execute([$reencrypted,$id]);$q->closeCursor();
    Check::same($rootBefore,$e->pdo->query('SELECT revision,history_digest FROM sosecurity_outbox_roots')->fetch(PDO::FETCH_ASSOC));
    $claim=$s->claim('tenant','accounts','worker');Check::same($payload,$claim->message()->body());Check::same($message->fingerprint(),$claim->message()->fingerprint());
    $current=new Notifications('two',['two'=>str_repeat('b',32)],$e->clock);Check::same($notice->encode(),$current->open($reencrypted,'tenant',$id,'verify_registration')->encode());Check::same(true,$s->acknowledge('tenant','accounts','worker',$claim->token()));
    $e->pdo->exec('BEGIN IMMEDIATE');try{$q=$e->pdo->prepare('INSERT INTO account_test_notices VALUES(?,?)');$q->execute([str_repeat('e',64),$reencrypted]);$q->closeCursor();$s->enqueue(new SoSecurity\Outbox\Message('tenant','accounts',SoSecurity\Outbox\Message::identifier('rolled-back-notice',$e->clock->time),'mail','account.notice','subject-2','{}'),'alice');$e->pdo->exec('ROLLBACK');}catch(Throwable $error){$e->pdo->exec('ROLLBACK');throw $error;}
    Check::same(1,(int)$e->observer->query('SELECT COUNT(*) FROM account_test_notices')->fetchColumn());Check::same(1,$e->count(true));
});
echo 'PASS account lifecycle foundation: '.Check::$assertions.' assertions on PHP '.PHP_VERSION.'; IDNA='.($idna?'positive':'dependency refusal')."; private SQLite notification/Outbox composition, not a complete account workflow\n";
