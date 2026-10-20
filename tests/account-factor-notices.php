<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
require dirname(__DIR__).'/examples/SqlAccounts.php';

use SoSecurity\Account\Address;
use SoSecurity\Account\FactorNotices;
use SoSecurity\Account\MailMessage;
use SoSecurity\Account\MailResult;
use SoSecurity\Account\MailTemplates;
use SoSecurity\Account\MailTransport;
use SoSecurity\Account\Notifications;
use SoSecurity\Account\SendBudgets;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\RateLimit\BudgetPolicy;
use SoSecurity\Storage\FileStore;
use SoSecurity\Storage\StorageException;
use SoSecurity\Support\HmacKeys;

final class FactorNoticeTransport implements MailTransport {
    public $sent=0;
    public function name():string {return 'local-relay';}
    public function send(MailMessage $message,int $milliseconds,callable $gate):MailResult {Check::same(true,$gate());++$this->sent;return new MailResult('accepted','smtp.accepted');}
}

$dir=privateDirectory();
try{
    $pdo=new PDO('sqlite:'.$dir.'/notices.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>2]);
    foreach(['account','account-example','outbox'] as $part){$sql=preg_replace('/^--.*$/m','',file_get_contents(dirname(__DIR__).'/resources/sql/'.$part.'-sqlite.sql'));foreach(explode(';',$sql) as $statement){if(trim($statement)!==''){$pdo->exec($statement);}}}
    chmod($dir.'/notices.sqlite',0600);$observer=new PDO('sqlite:'.$dir.'/notices.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $clock=new TestClock();$accounts=new SoSecurity\Account\Example\SqlAccounts($pdo);$pending=$accounts->createPending('tenant','user',new Address('owner@example.test'));$accounts->activate($pending,(new SoSecurity\Password\PasswordHasher('bcrypt',['cost'=>10]))->hash('Local test password 49!'));
    $publishAllowed=true;$deliveryAllowed=true;$manage=static function():bool{return true;};
    $publish=static function(string $action,string $phase,string $scope,$context)use(&$publishAllowed):bool{return $publishAllowed;};
    $delivery=static function(string $action,string $phase,string $scope,$record)use(&$deliveryAllowed):bool{return $deliveryAllowed;};
    $source=new FactorNotices($pdo,'factor-notice-test','tenant',str_repeat('e',64),new HmacKeys('account',['account'=>str_repeat('a',32)]),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$accounts,new Notifications('notice',['notice'=>str_repeat('n',32)],$clock),$manage,$publish,$delivery,null,$clock);
    $source->initialize();$operation=str_repeat('1',64);$pdo->exec('BEGIN IMMEDIATE');$id=$source->publish('factor_privileged_revoked','user',$operation);Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());$pdo->exec('COMMIT');
    Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());Check::same('factor_privileged_revoked',$source->notificationForDispatch($id)->notice()->type());
    $deliveryAllowed=false;Check::throws(SecurityException::class,static function()use($source,$id):void{$source->notificationForDispatch($id);});$deliveryAllowed=true;
    $publishAllowed=false;$pdo->exec('BEGIN IMMEDIATE');Check::throws(SecurityException::class,static function()use($source):void{$source->publish('factor_management_completed','user',str_repeat('2',64));});$pdo->exec('ROLLBACK');$publishAllowed=true;
    $pdo->exec('BEGIN IMMEDIATE');$rolled=$source->publish('factor_management_completed','user',str_repeat('2',64));$pdo->exec('ROLLBACK');Check::same(null,$source->notificationForDispatch($rolled));Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());Check::same(1,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_outbox_records')->fetchColumn());
    Check::throws(ValidationException::class,static function()use($source):void{$source->publish('factor_unknown','user',str_repeat('3',64));});Check::throws(ValidationException::class,static function()use($source):void{$source->publish('factor_management_completed','user',str_repeat('3',65));});
    $urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $type){$urls[$type]='https://account.example.test/'.$type;}$templates=new MailTemplates('factor-notice-test',new Address('security@example.test'),$urls);
    $policies=[];foreach(['site','transport','target','subject'] as $name){$policies[$name]=new BudgetPolicy('fixed_window',1,60);}mkdir($dir.'/budgets',0700);$budgets=new SendBudgets(new FileStore($dir.'/budgets','factor-notice-budget',$clock),'factor-notice-test',str_repeat('b',32),$policies,$clock,1);
    $transport=new FactorNoticeTransport();$worker=$source->dispatcher('worker',$budgets,$templates,$transport,static function():bool{return true;});$result=$worker->sendNext();Check::same('submitted',$result['state']);Check::same(1,$transport->sent);Check::same('idle',$worker->sendNext()['state']);
    $pdo->exec('BEGIN IMMEDIATE');$second=$source->publish('factor_management_started','user',str_repeat('4',64));$pdo->exec('COMMIT');Check::same('deferred',$worker->sendNext()['state']);Check::same(1,$transport->sent);Check::same('factor_management_started',$source->notificationForDispatch($second)->notice()->type());
    $beforeNotice=$source->notificationForDispatch($id)->notice()->encode();$beforeQueue=$observer->query('SELECT payload_body,payload_digest,created_at FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC);
    $rotatedCodec=new Notifications('new',['notice'=>str_repeat('n',32),'new'=>str_repeat('z',32)],$clock);
    $rotated=new FactorNotices($pdo,'factor-notice-test','tenant',str_repeat('e',64),new HmacKeys('new',['account'=>str_repeat('a',32),'new'=>str_repeat('x',32)]),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$accounts,$rotatedCodec,$manage,$publish,$delivery,null,$clock);
    $page=$rotated->rotate(1);Check::same(1,$page['reencrypted']);Check::same(1,$page['resealed']);Check::same(true,$page['root_rotated']);Check::same(false,$page['done']);
    $earlyRetired=new FactorNotices($pdo,'factor-notice-test','tenant',str_repeat('e',64),new HmacKeys('new',['new'=>str_repeat('x',32)]),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$accounts,new Notifications('new',['new'=>str_repeat('z',32)],$clock),$manage,$publish,$delivery,null,$clock);$pendingId=$page['next']===$id?$second:$id;
    Check::throws(StorageException::class,static function()use($earlyRetired,$pendingId):void{$earlyRetired->notificationForDispatch($pendingId);});
    $page=$rotated->rotate(1,$page['next']);Check::same(1,$page['reencrypted']);Check::same(1,$page['resealed']);Check::same(false,$page['root_rotated']);Check::same(true,$rotated->rotate(1,$page['next'])['done']);
    Check::same($beforeQueue,$observer->query('SELECT payload_body,payload_digest,created_at FROM sosecurity_outbox_records ORDER BY order_no')->fetchAll(PDO::FETCH_ASSOC));
    Check::same(['new'],array_values(array_unique($observer->query('SELECT seal_key FROM sosecurity_account_records')->fetchAll(PDO::FETCH_COLUMN))));Check::same('new',$observer->query('SELECT seal_key FROM sosecurity_account_roots')->fetchColumn());
    $retired=new FactorNotices($pdo,'factor-notice-test','tenant',str_repeat('e',64),new HmacKeys('new',['new'=>str_repeat('x',32)]),new HmacKeys('outbox',['outbox'=>str_repeat('o',32)]),$accounts,new Notifications('new',['new'=>str_repeat('z',32)],$clock),$manage,$publish,$delivery,null,$clock);
    Check::same($beforeNotice,$retired->notificationForDispatch($id)->notice()->encode());Check::same('factor_management_started',$retired->notificationForDispatch($second)->notice()->type());$source=$retired;
    $pdo->exec("UPDATE account_example SET address='changed@example.test' WHERE scope='tenant' AND subject='user'");Check::same(null,$source->notificationForDispatch($second));
    $clock->time+=86401;Check::same(2,$source->maintain(20)['removed']);Check::same(0,(int)$observer->query('SELECT COUNT(*) FROM sosecurity_account_records')->fetchColumn());
    echo 'PASS factor notices: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; local SQLite atomic publication, current read, lease and send budget\n";
}finally{$observer=null;$pdo=null;foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $entry){if($entry->isDir()){rmdir($entry->getPathname());}else{unlink($entry->getPathname());}}rmdir($dir);}
