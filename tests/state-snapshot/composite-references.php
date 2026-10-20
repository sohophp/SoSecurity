<?php
declare(strict_types=1);
require __DIR__.'/support.php';
final class ReferenceStateSource implements SoSecurity\Account\StateSnapshot
{
    private $pdo;private $name;public $calls=0;
    public function __construct(PDO $pdo,string $name){$this->pdo=$pdo;$this->name=$name;}
    public function connection():PDO{return $this->pdo;}
    public function fingerprint():string{return hash('sha256',$this->name);}
    public function digest():string{++$this->calls;return hash('sha256',$this->name.'-state');}
}
$pdo=new PDO('sqlite::memory:');$one=new ReferenceStateSource($pdo,'one');$two=new ReferenceStateSource($pdo,'two');$selected=$one;$sources=['chosen'=>&$selected];$composite=new SoSecurity\Account\CompositeStateSnapshot($pdo,$sources);$before=$composite->digest();$fp=$composite->fingerprint();$selected=$two;
try{$after=$composite->digest();}catch(SoSecurity\Exception\ConfigurationException $error){throw new RuntimeException('UNSAFE_COMPOSITE_INPUT_REFERENCE_CHANGED_FROZEN_COVERAGE');}
Check::same($before,$after);Check::same($fp,$composite->fingerprint());Check::same(4,$one->calls);Check::same(0,$two->calls);
unset($sources['chosen']);Check::same($before,$composite->digest());Check::same(6,$one->calls);
echo 'PASS immutable composite references: '.Check::$assertions.' assertions PHP '.PHP_VERSION."; replacing or removing caller array references never changes captured providers\n";
