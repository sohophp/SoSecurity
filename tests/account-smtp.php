<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$config=json_decode(file_get_contents($argv[1]),true);$urls=[];foreach(['verify_registration','verify_address_old','verify_address_new','cancel_change','recover_account'] as $type){$urls[$type]='https://account.example.test/'.$type;}
$recipient=new SoSecurity\Account\Address($config['utf8']?'用户@example.test':'owner@example.test',$config['utf8']);$notice=new SoSecurity\Account\Notice('tenant',str_repeat('a',64),'recover_account',$recipient,str_repeat('b',64),100000,100900);$message=(new SoSecurity\Account\MailTemplates('site',new SoSecurity\Account\Address('security@example.test'),$urls,'Owned local mail test','zh-CN'))->render(new SoSecurity\Account\DispatchNotice($notice,str_repeat('c',64),'account'));
$transport=new SoSecurity\Account\SmtpTransport('local-test',$config['host'],$config['port'],'127.0.0.1',$config['mode'],$config['auth']?['username'=>'owned-user','password'=>'owned-password']:null,$config['mode']==='unix'?null:$config['ca'],$config['socket'] ?? null,$config['utf8'],'client.example.test');
$calls=0;$start=microtime(true);$result=$transport->send($message,$config['milliseconds'],static function()use(&$calls,$config):bool{++$calls;return !$config['gate_false'];});$elapsed=microtime(true)-$start;
echo json_encode(['state'=>$result->state(),'code'=>$result->code(),'retryable'=>$result->retryable(),'gate_calls'=>$calls,'elapsed'=>$elapsed,'peak'=>memory_get_peak_usage(true),'private_export'=>strpos(var_export($transport,true),'owned-password')===false,'message_id'=>$message->messageId()])."\n";
