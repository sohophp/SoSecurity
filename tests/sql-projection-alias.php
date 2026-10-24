<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
use SoSecurity\Support\SqlSchema;
use SoSecurity\Exception\ConfigurationException;
$types=['format'=>'int','namespace'=>'digest'];
Check::same('CASE WHEN format>=0 AND format<=9223372036854775807 THEN format ELSE NULL END AS format,CASE WHEN octet_length(namespace)<=64 THEN namespace ELSE NULL END AS namespace',SqlSchema::boundedProjection('mysql',$types));
Check::same("CASE WHEN typeof(format)='integer' AND format>=0 THEN format ELSE NULL END AS format,CASE WHEN typeof(namespace)='text' AND length(CAST(namespace AS BLOB))<=64 THEN namespace ELSE NULL END AS namespace",SqlSchema::boundedProjection('sqlite',$types));
$pdo=new PDO('sqlite::memory:',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$pdo->exec('CREATE TABLE records(format,namespace,payload)');$q=$pdo->prepare('INSERT INTO records VALUES(1,?,?)');$q->bindValue(1,str_repeat('a',64));$q->bindValue(2,"a\0b",PDO::PARAM_LOB);$q->execute();
$sql='SELECT '.SqlSchema::boundedProjection('sqlite',$types,'r','r_').','.SqlSchema::blobLength('sqlite','payload','r').' AS bytes FROM records r';
$row=$pdo->query($sql)->fetch(PDO::FETCH_ASSOC);$row['r_format']=SqlSchema::integer($row['r_format']);$row['bytes']=SqlSchema::integer($row['bytes']);Check::same(['r_format'=>1,'r_namespace'=>str_repeat('a',64),'bytes'=>3],$row);
$pdo->exec("UPDATE records SET format=-1,namespace=replace(hex(zeroblob(33)),'0','x'),payload='text'");
$row=$pdo->query($sql)->fetch(PDO::FETCH_ASSOC);Check::same(null,$row['r_format']);Check::same(null,$row['r_namespace']);Check::same('-1',(string)$row['bytes']);
foreach(['x.y','x;drop','',str_repeat('a',17)] as $alias){Check::throws(ConfigurationException::class,static function()use($types,$alias):void{SqlSchema::boundedProjection('mysql',$types,$alias);});Check::throws(ConfigurationException::class,static function()use($alias):void{SqlSchema::blobLength('mysql','payload',$alias);});}
foreach(['x.y','x;drop','missing',str_repeat('a',17).'_'] as $prefix){Check::throws(ConfigurationException::class,static function()use($types,$prefix):void{SqlSchema::boundedProjection('mysql',$types,'r',$prefix);});}
echo 'PASS bounded SQL projection aliases '.Check::$assertions.' PHP '.PHP_VERSION.PHP_EOL;
