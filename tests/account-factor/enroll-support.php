<?php
declare(strict_types=1);
require __DIR__.'/operations-support.php';
function ownedEnrollment(SoSecurity\Account\FactorOperations $s,ManagedEnvironment $e):array
{
    $review=$s->review('enroll','user','owned-enrollment-review');$prepared=$s->beginEnrollment($review,'owned-enrollment-start',normalProof());parse_str(parse_url($prepared->enrollment()->provisioningUri(),PHP_URL_QUERY),$parts);return [$review,$prepared,$parts['secret']];
}
function enrollmentCode(ManagedEnvironment $e,string $secret):string {return (new SoSecurity\Mfa\Totp())->codeAt($secret,$e->clock->time);}
function enrollmentReason(string $reason,callable $operation):void
{
    ++Check::$assertions;try{$operation();}catch(SoSecurity\Exception\SecurityException $error){Check::same($reason,$error->reason());return;}throw new RuntimeException('Expected '.$reason);
}
