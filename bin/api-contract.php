<?php
declare(strict_types=1);
// Reflection only: no component constructor, session, header, storage or optional provider initialization.
require dirname(__DIR__).'/vendor/autoload.php';
function apiType(?ReflectionType $type,ReflectionClass $declaring): ?array
{
    if ($type===null) { return null; }
    if (!$type instanceof ReflectionNamedType) { throw new RuntimeException('New type form requires an explicit compatibility review.'); }
    $name=$type->getName();
    // PHP 8.5 resolves self to the declaring class; older runtimes return the literal spelling.
    if ($name==='self') { $name=$declaring->getName(); }
    elseif ($name==='parent') { $parent=$declaring->getParentClass(); $name=$parent===false ? 'parent' : $parent->getName(); }
    return ['name'=>$name,'nullable'=>$type->allowsNull()];
}
$root=dirname(__DIR__);$classes=json_decode(file_get_contents($root.'/resources/api/classes.json'),true);
$contract=['schema'=>2,'classes'=>[]];
foreach ($classes as $name) {
    $reflection=new ReflectionClass($name);$parent=$reflection->getParentClass();$interfaces=array_values(array_filter($reflection->getInterfaceNames(),static function (string $interface): bool { return !(new ReflectionClass($interface))->isInternal(); }));sort($interfaces);
    $entry=['kind'=>$reflection->isInterface()?'interface':'class','final'=>$reflection->isFinal(),'abstract'=>$reflection->isAbstract(),
        'parent'=>$parent===false?null:$parent->getName(),'interfaces'=>$interfaces,'constants'=>[],'methods'=>[],'properties'=>[]];
    foreach ($reflection->getReflectionConstants() as $constant) {
        if ($constant->isPublic()) { $entry['constants'][$constant->getName()]=$constant->getValue(); }
    }
    ksort($entry['constants']);
    foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        $file=$method->getDeclaringClass()->getFileName();
        if ($file===false || strpos($file,$root.'/src/')!==0) { continue; }
        $parameters=[];
        foreach ($method->getParameters() as $parameter) {
            $parameters[]=['name'=>$parameter->getName(),'type'=>apiType($parameter->getType(),$method->getDeclaringClass()),'reference'=>$parameter->isPassedByReference(),
                'variadic'=>$parameter->isVariadic(),'optional'=>$parameter->isOptional(),'default'=>$parameter->isDefaultValueAvailable() ? $parameter->getDefaultValue() : null];
        }
        $entry['methods'][$method->getName()]=['static'=>$method->isStatic(),'return'=>apiType($method->getReturnType(),$method->getDeclaringClass()),'parameters'=>$parameters];
    }
    $defaults=$reflection->getDefaultProperties();
    foreach ($reflection->getProperties(ReflectionProperty::IS_PUBLIC) as $property) {
        $entry['properties'][$property->getName()]=['static'=>$property->isStatic(),'default'=>$defaults[$property->getName()] ?? null];
    }
    ksort($entry['methods']);ksort($entry['properties']);$contract['classes'][$name]=$entry;
}
$json=json_encode($contract,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
$target=$root.'/resources/api/candidate.json';
if (($argv[1] ?? null)==='--write') {
    $target=$argv[2] ?? $target;
    if (file_put_contents($target,$json)!==strlen($json)) { throw new RuntimeException('Cannot write API proposal.'); }
    echo 'WROTE public API candidate for '.count($classes)." classes/interfaces; review required before release freeze\n";
} else {
    if (!is_file($target) || file_get_contents($target)!==$json) { fwrite(STDERR,"FAIL public API changed; inspect and explicitly revise the candidate contract after review\n");exit(1); }
    echo 'PASS public API signatures: '.count($classes).' classes/interfaces on PHP '.PHP_VERSION."\n";
}
