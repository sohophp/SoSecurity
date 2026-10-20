<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';require __DIR__.'/outbox-support.php';
outboxCase(false,static function(OutboxEnvironment $e):void{
    $s=$e->service();$s->initialize('tenant','orders','admin');$m=$e->message('owned-private-event','SYNTHETIC-PRIVATE-OUTBOX-BODY');$e->append($s,$m);$c=$s->claim('tenant','orders','worker');
    foreach([$m,$c] as $object){foreach([var_export($object,true),print_r($object,true),json_encode($object)] as $dump){Check::same(false,strpos($dump,$m->body())!==false);Check::same(false,strpos($dump,$c->token())!==false);}$class=get_class($object);Check::throws(SoSecurity\Exception\ConfigurationException::class,static function()use($class):void{unserialize('O:'.strlen($class).':"'.$class.'":0:{}');});}
    Check::same($m->body(),$c->message()->body());Check::same(true,$s->acknowledge('tenant','orders','worker',$c->token()));
});
echo 'PASS Outbox private claim/message exports: '.Check::$assertions.' assertions on PHP '.PHP_VERSION."; explicit getters retain original bytes/tokens, automatic exports and wakeup do not expose them\n";
