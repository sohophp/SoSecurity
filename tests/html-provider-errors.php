<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Output\HtmlCleaner;
use SoSecurity\Output\HtmlSanitizer;
use SoSecurity\Exception\SecurityException;
$mode=$argv[1]??'exception';
if($mode==='exception'){
 $provider=new class implements HtmlSanitizer {public function sanitize(string $html):string{throw new RuntimeException('PRIVATE-SANITIZER-DATA',0,new LogicException('PRIVATE-SANITIZER-INNER'));}};
 try{(new HtmlCleaner($provider))->clean('<p>Owned input</p>');throw new RuntimeException('Provider failure accepted');}catch(SecurityException $error){Check::same('html.provider',$error->reason());Check::same(null,$error->getPrevious());Check::same(false,strpos($error->getMessage(),'PRIVATE-')!==false);}
}else{
 foreach(["\0","\x01","\x08","\x0b","\x0c","\x0e","\x1f","\x7f","\xff"] as $bad){
  $provider=new class($bad) implements HtmlSanitizer {private $output;public function __construct(string $output){$this->output=$output;}public function sanitize(string $html):string{return $this->output;}};
  try{(new HtmlCleaner($provider))->clean('owned');throw new RuntimeException('Invalid provider output accepted');}catch(SecurityException $error){Check::same('html.output',$error->reason());Check::same(null,$error->getPrevious());}
 }
 $provider=new class implements HtmlSanitizer {public function sanitize(string $html):string{return "<p>中文\t\r\n</p>";}};
 Check::same("<p>中文\t\r\n</p>",(new HtmlCleaner($provider))->clean('owned'));
}
echo 'PASS HTML provider '.$mode.' '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
