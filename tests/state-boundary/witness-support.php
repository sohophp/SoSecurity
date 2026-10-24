<?php
declare(strict_types=1);
function witnessPersist($handle,string $directory):bool{return (new SoSecurity\Account\LocalStatePersistence($directory,5000))($handle);}
function snapshotPersist($handle,string $directory):bool{return witnessPersist($handle,$directory);}
function witnessBudget():bool{return true;}
function witnessReason(string $reason,callable $body):void{++Check::$assertions;try{$body();}catch(SoSecurity\Exception\SecurityException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected '.$reason);}
