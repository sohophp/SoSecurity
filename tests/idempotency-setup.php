<?php
declare(strict_types=1);
require __DIR__.'/bootstrap.php';
$input=json_decode(stream_get_contents(STDIN),true);$store=new SoSecurity\Storage\FileStore($input['directory'],'idempotency-example');$api=new SoSecurity\Api\ApiKeys($store);
if(($input['mode'] ?? '')==='entry_budget'){$budget=new SoSecurity\RateLimit\RateLimiter($store,new SoSecurity\RateLimit\Policy(240,60,[10],120));for($i=0;$i<240;++$i){$budget->consume('idempotency.entry','127.0.0.1');}echo json_encode(['blocked'=>!$budget->consume('idempotency.entry','127.0.0.1')->allowed]);return;}
$credential=$api->issue($input['subject'],$input['scopes'] ?? ['orders:create'],$input['ttl'] ?? 120);echo json_encode(['token'=>$credential->token(),'id'=>$credential->identity()->id()]);
