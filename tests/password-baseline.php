<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$list=SoSecurity\Password\PasswordBlocklist::baseline();$property=new ReflectionProperty(get_class($list),'digests');if(PHP_VERSION_ID<80100){$property->setAccessible(true);}$keys=array_keys($property->getValue($list));sort($keys);
// Golden digest of the complete previous public baseline, established before the allocation change.
Check::same(7618,$list->count());Check::same('65048ba83b6f99565c06827a651c43755484b17555edd13e57adaab8f9cd6b3a',hash('sha256',implode("\n",$keys)));
foreach(['password','Password1!',str_repeat('a',128),str_repeat('abcdef',21)] as $password){Check::same(true,$list->contains($password));}
foreach(['unique owner phrase 81492!',"a\0b",'独立安全验证口令'] as $password){Check::same(false,$list->contains($password));}
echo 'PASS unchanged password baseline: '.Check::$assertions.' assertions, 7618 digest golden set, PHP '.PHP_VERSION."\n";
