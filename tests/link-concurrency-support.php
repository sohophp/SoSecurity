<?php
declare(strict_types=1);
function concurrentLinks(SoSecurity\Storage\AtomicStore $store,TestClock $clock):array
{
    $target=new SoSecurity\Link\Target('document.read',new SoSecurity\Authorization\Resource('link-concurrency','document','a','1'),'/document',['id'=>'a']);
    $links=new SoSecurity\Link\Links($store,new SoSecurity\Support\HmacKeys('test',['test'=>str_repeat('l',32)]),'link-concurrency',new SoSecurity\Link\Policy('https://links.example',300,86400,8),static function(){return true;},$clock);
    return [$links,$target];
}
