<?php
declare(strict_types=1);
require $argv[1];
final class PrivatePsrSubject {
 private $secret='PRIVATE-PSR15-SUBJECT';
 public function __invoke(\Psr\Http\Message\ServerRequestInterface $request):string{return 'owned-subject';}
}
$middleware=new SoSecurity\Psr15\BudgetMiddleware(new SoSecurity\RateLimit\BudgetLimiter(new SoSecurity\Storage\MemoryStore(),new SoSecurity\RateLimit\BudgetPolicy()),'owned',new PrivatePsrSubject(),new Nyholm\Psr7\Response(429,[], 'PRIVATE-PSR15-DENIAL'));
foreach(['export','dump','serialize','wakeup'] as $mode){
 if(isset($argv[2])&&$argv[2]!==$mode){continue;}
 if(in_array($mode,['serialize','wakeup'],true)){
  $refused=false;try{if($mode==='serialize'){serialize($middleware);}else{$class=SoSecurity\Psr15\BudgetMiddleware::class;unserialize('O:'.strlen($class).':"'.$class.'":0:{}');}}catch(SoSecurity\Exception\ConfigurationException $error){$refused=true;}
  if(!$refused){throw new RuntimeException('Middleware serialization must be refused explicitly');}
 }else{
  if($mode==='export'){$out=var_export($middleware,true);}else{ob_start();var_dump($middleware);$out=ob_get_clean();}
  if(strpos($out,'PRIVATE-PSR15-')!==false){throw new RuntimeException('Middleware diagnostics exposed retained host dependencies');}
 }
 echo 'PASS PSR15 privacy '.$mode.' PHP '.PHP_VERSION.PHP_EOL;
}
