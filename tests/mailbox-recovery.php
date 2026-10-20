<?php
declare(strict_types=1);
require __DIR__.'/mailbox-recovery-support.php';
foreach([false,true] as $mfa){mailboxCase(static function(MailboxEnvironment $m)use($mfa):void{
    $e=$m->e;$before=$e->account();$session=$m->r->t->credential->token();$factor=$m->r->factor===null?null:$m->r->factor->binding('tenant',$m->r->t->subject);$d=$m->begin();
    Check::same('recover_address',$d->notice()->type());Check::same('rescued@example.com',$d->notice()->recipient()->value());Check::same(2,count($m->ids()));Check::same($before,$e->account());
    Check::same(true,$m->confirm($d));$after=$e->account();Check::same('rescued@example.com',$after['address']);foreach(['subject','password','roles','mfa_required','status','verified'] as $field){Check::same($before[$field],$after[$field]);}
    Check::same(false,$before['credential_version']===$after['credential_version']);Check::same(false,$before['address_version']===$after['address_version']);Check::same(null,$m->r->t->sessions->verify('tenant',$m->r->t->subject,$session));Check::same($factor,$m->r->factor===null?null:$m->r->factor->binding('tenant',$m->r->t->subject));Check::same(false,$m->confirm($d));
    Check::same(['verify','current','commit','complete'],$m->phases);Check::same(1,count(array_unique($m->contexts)));$request=$m->requests[0];Check::same('recover_address',$request->purpose());Check::same('owner@example.com',$request->record()->address()->value());Check::same('rescued@example.com',$request->target()->value());Check::same($d->notice()->expiresAt(),$request->expiresAt());
    $types=[];$recipients=[];foreach($m->ids() as $id){$n=$m->service->notification($id);if($n!==null){$types[]=$n->notice()->type();$recipients[]=$n->notice()->recipient()->value();Check::same('',$n->notice()->token());}}
    Check::same(['address_recovery_started','address_recovered','address_recovered'],$types);Check::same(['owner@example.com','owner@example.com','rescued@example.com'],$recipients);
},$mfa);}
mailboxCase(static function(MailboxEnvironment $m):void{$d=$m->begin();$before=$m->e->account();$m->approved=false;Check::same(false,$m->confirm($d));Check::same($before,$m->e->account());Check::same(2,count($m->ids()));Check::same(['verify'],$m->phases);});
mailboxCase(static function(MailboxEnvironment $m):void{$d=$m->begin();$before=$m->e->account();Check::same(false,$m->confirm($d,str_repeat('0',64)));Check::same([],$m->phases);Check::same($before,$m->e->account());Check::same(true,$m->confirm($d));});
echo 'PASS isolated mailbox recovery core: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; explicit test approval, new mailbox proof, actual account/version/session preservation, no factor replacement or HTTP acceptance\n";
