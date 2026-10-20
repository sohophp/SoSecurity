<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Outbox;

use PDO;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Outbox\Message;
use SoSecurity\Outbox\SqlOutbox;
use SoSecurity\Support\HmacKeys;

const SITE='outbox-native-example';
const SCOPE='outbox-example';
const PRODUCER='orders';
const PUBLISHER='outbox-publisher';
require_once __DIR__.'/outbox-authority.php';
require_once __DIR__.'/outbox-recovery.php';
require_once __DIR__.'/outbox-resolution.php';

// Import is inert. The host explicitly invokes adapters with its private, existing state.
function identifier($value):string
{
    if(!is_string($value)||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$value)){throw new ValidationException('Use a bounded server identity.','outbox_example.input');}return $value;
}
function privateFile($path,?string $web=null):string
{
    $real=is_string($path)?realpath($path):false;
    if($real===false||$real!==$path||!is_file($real)||is_link($path)||(fileperms($real)&0077)!==0||(fileperms(dirname($real))&0077)!==0||($web!==null&&($real===$web||strpos($real,rtrim($web,'/').'/')===0))){throw new \RuntimeException('Configure an existing canonical private file outside the web root.');}return $real;
}
function jsonFile(string $file,int $maximum=16384):array
{
    $raw=file_get_contents($file,false,null,0,$maximum+1);$data=is_string($raw)&&strlen($raw)<=$maximum?json_decode($raw,true,8):null;
    if(!is_array($data)){throw new \RuntimeException('Invalid bounded private configuration.');}return $data;
}
function keyData(string $file):array
{
    $data=jsonFile($file);
    if(count($data)!==2||!is_string($data['current'] ?? null)||!is_array($data['keys'] ?? null)||!isset($data['keys'][$data['current']])||count($data['keys'])>8){throw new \RuntimeException('Invalid key snapshot.');}
    $keys=[];foreach($data['keys'] as $id=>$encoded){$key=is_string($encoded)?base64_decode($encoded,true):false;if(!is_string($key)||strlen($key)!==32||base64_encode($key)!==$encoded){throw new \RuntimeException('Invalid key encoding.');}$keys[$id]=$key;}
    new HmacKeys($data['current'],$keys);return ['current'=>$data['current'],'keys'=>$keys];
}
function sealingKeys(string $file):HmacKeys {$data=keyData($file);return new HmacKeys($data['current'],$data['keys']);}
function settings(string $role,?string $actualWeb=null):array
{
    if(!in_array($role,['sender','receiver'],true)){throw new \RuntimeException('Use a fixed adapter role.');}
    $file=privateFile(getenv('SOSECURITY_OUTBOX_EXAMPLE_CONFIG'));$data=jsonFile($file);
    $required=['role','document_root','database','storage','actor','version','epoch','seals','wire_keys','url'];if($role==='receiver'){$required=array_merge($required,['checkpoint_database','checkpoint_lock']);}$allowed=array_merge($required,['idempotency_keys','policy','resolution_keys','authority_database']);if($role==='sender'){$allowed=array_merge($allowed,['transport_budget_ms','receiver_epoch','resolution_archive']);}
    if(array_diff($required,array_keys($data))||array_diff(array_keys($data),$allowed)||$data['role']!==$role){throw new \RuntimeException('Explicit adapter configuration required.');}
    $web=is_string($data['document_root'])?realpath($data['document_root']):false;
    if($web===false||$web!==$data['document_root']||!is_dir($web)||($actualWeb!==null&&realpath($actualWeb)!==$web)){throw new \RuntimeException('Use the actual canonical document root.');}
    privateFile($file,$web);foreach(['database','seals','wire_keys'] as $field){$data[$field]=privateFile($data[$field],$web);}
    if($role==='sender'){$data['idempotency_keys']=privateFile($data['idempotency_keys'] ?? null,$web);if($data['idempotency_keys']===$data['seals']||$data['idempotency_keys']===$data['wire_keys']){throw new \RuntimeException('Separate protocol keys.');}}
    if($data['seals']===$data['wire_keys']){throw new \RuntimeException('Separate transport and state keys.');}
    $sets=[keyData($data['seals'])['keys'],keyData($data['wire_keys'])['keys']];if($role==='sender'){$sets[]=keyData($data['idempotency_keys'])['keys'];}
    foreach($sets as $index=>$keys){foreach($sets as $other=>$otherKeys){if($other<=$index){continue;}foreach($keys as $key){foreach($otherKeys as $otherKey){if(hash_equals($key,$otherKey)){throw new \RuntimeException('Use independent protocol key material.');}}}}}
    identifier($data['actor']);identifier($data['version']);if(!is_string($data['epoch'])||!preg_match('/\A[a-f0-9]{64}\z/D',$data['epoch'])){throw new \RuntimeException('Use an external deployment epoch.');}
    $uri=\SoSecurity\Http\Uri::parse(is_string($data['url'])?$data['url']:'');
    if($uri->scheme()!=='https'||$uri->url()!==$data['url']||strpos($uri->target(),'?')!==false||strpos($data['url'],'#')!==false||(filter_var($uri->hostName(),FILTER_VALIDATE_IP)!==false&&!\SoSecurity\Http\Outbound\PublicAddress::allows($uri->hostName()))){throw new \RuntimeException('Use a fixed canonical public HTTPS receiver URL.');}
    new \SoSecurity\Http\Outbound\Policy(['hosts'=>[$uri->hostName()],'ports'=>[$uri->port()]]);
    $store=realpath(is_string($data['storage'])?$data['storage']:'');
    if($store===false||$store!==$data['storage']||$store===$web||strpos($store,rtrim($web,'/').'/')===0){throw new \RuntimeException('Configure existing private state outside the web root.');}
    $data['store']=new \SoSecurity\Storage\FileStore($store,SCOPE.'-'.$role);
    if(isset($data['policy'])&&!is_array($data['policy'])){throw new \RuntimeException('Use an explicit policy map.');}
    $data['policy']=(new \SoSecurity\Outbox\Policy(array_replace(['maximum_payload_bytes'=>8192],$data['policy'] ?? [])))->options();
    if($data['policy']['maximum_payload_bytes']>8192){throw new \RuntimeException('This adapter uses an 8192-byte payload profile.');}
    if($role==='sender'){$data['resolution_archive']=array_key_exists('resolution_archive',$data)?$data['resolution_archive']:false;if(!is_bool($data['resolution_archive'])){throw new \RuntimeException('Use an explicit archive feature flag.');}$data['transport_budget_ms']=array_key_exists('transport_budget_ms',$data)?$data['transport_budget_ms']:1000;if(!is_int($data['transport_budget_ms'])||$data['transport_budget_ms']<100||$data['transport_budget_ms']>10000){throw new \RuntimeException('Use an explicit bounded network budget.');}}
    if($role==='receiver'){
        foreach(['checkpoint_database','checkpoint_lock'] as $field){$data[$field]=privateFile($data[$field],$web);}
        $paths=[$data['database'],$data['checkpoint_database'],$data['checkpoint_lock']];$identities=[];$data['receiver_files']=[];foreach($paths as $path){clearstatcache(true,$path);$stat=stat($path);$identity=$stat['dev'].':'.$stat['ino'];if(isset($identities[$identity])){throw new \RuntimeException('Use independent business, witness and lock files.');}$identities[$identity]=true;$data['receiver_files'][$path]=$identity;}
    }
    if($role==='sender'){clearstatcache(true,$data['database']);$stat=stat($data['database']);$data['sender_file_identity']=$stat['dev'].':'.$stat['ino'];}
    $data['pdo']=new PDO('sqlite:'.$data['database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
    $data['configuration_file']=$file;
    $data=authoritySetup($data);
    if($role==='receiver'){$data['checkpoint_pdo']=new PDO('sqlite:'.$data['checkpoint_database'],null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);receiverDeployment($data);}
    return $data;
}
/** @phpstan-impure Reads current database authority on every call. */
function principal(array $settings,string $role,?string $actor=null):bool
{
    return authorityAllows($settings,[$role],null,false,$actor);
}
function event(string $body):array
{
    $data=strlen($body)<=8192?json_decode($body,true,4):null;$fields=['event_id','order_id','reference','subject','amount','created_at','tenant','topic'];
    if(!is_array($data)||count($data)!==count($fields)||array_diff(array_keys($data),$fields)||substr_count($body,':')!==8){throw new ValidationException('Use the fixed scalar event schema without duplicate JSON members.','outbox_example.input');}
    foreach(['reference','subject'] as $field){identifier($data[$field]);}
    if(!is_string($data['order_id'])||!preg_match('/\A[a-f0-9]{32}\z/D',$data['order_id'])||!is_int($data['amount'])||$data['amount']<1||$data['amount']>1000000||!is_int($data['created_at'])||$data['created_at']<1||$data['created_at']>PHP_INT_MAX-31536001||$data['tenant']!==SCOPE||$data['topic']!=='order.created'||!is_string($data['event_id'])||$data['event_id']!==Message::identifier($data['order_id'],$data['created_at'])){throw new ValidationException('Invalid event values.','outbox_example.input');}return $data;
}
function order(array $settings,string $eventId):?array
{
    if(strlen($eventId)>96){return null;}
    $q=$settings['pdo']->prepare("SELECT subject,reference_id,order_id,amount,created_at,event_id,payload FROM outbox_example_orders WHERE event_id=:event AND typeof(payload)='blob' AND length(payload)<=8192 AND length(CAST(subject AS BLOB))<=64 AND length(CAST(reference_id AS BLOB))<=64 AND length(CAST(order_id AS BLOB))=32 AND typeof(amount)='integer' AND amount BETWEEN 1 AND 1000000 AND typeof(created_at)='integer' AND created_at>0");$q->execute(['event'=>$eventId]);$row=$q->fetch(PDO::FETCH_ASSOC);$q->closeCursor();if(!is_array($row)||!is_string($row['payload'])){return null;}
    $data=event($row['payload']);foreach(['subject'=>'subject','reference'=>'reference_id','order_id'=>'order_id','event_id'=>'event_id'] as $key=>$column){if($data[$key]!==$row[$column]){return null;}}
    if($data['amount']!==(int)$row['amount']||$data['created_at']!==(int)$row['created_at']){return null;}return $data+['body'=>$row['payload']];
}
function message(array $data,string $body):Message {return new Message(SCOPE,PRODUCER,$data['event_id'],'receiver','order.created',$data['order_id'],$body);}
function outbox(array $settings):SqlOutbox
{
    $authority=static function(string $action,string $phase,string $scope,string $producer,string $actor,array $metadata)use($settings):bool{
        $role=$action==='enqueue'?'orders_writer':'outbox_worker';$managementRead=in_array($action,['status','candidates'],true)&&resolutionPrincipal($settings);
        if($scope!==SCOPE||$producer!==PRODUCER||$actor!==$settings['actor']||(!$managementRead&&!principal($settings,$role))){return false;}
        if(!isset($metadata['id'])){return true;}$data=order($settings,$metadata['id']);
        return $data!==null&&($action!=='enqueue'||$data['subject']===$actor)&&($managementRead||principal($settings,'orders_writer',$data['subject']))&&hash_equals(message($data,$data['body'])->fingerprint(),$metadata['fingerprint']);
    };
    $manager=static function(string $action,string $phase,string $scope,string $producer,string $actor,array $metadata)use($settings):bool{
        if($scope!==SCOPE||$producer!==PRODUCER||$actor!==$settings['actor']||!principal($settings,'outbox_admin')){return false;}
        if($action==='reconcile'){return resolutionPrincipal($settings);}
        return $action!=='purge_resolution'||resolutionGcAllowed($settings,$metadata);
    };
    return \SoSecurity\Security::fromArray(['site'=>SITE,'outbox'=>['connection'=>'db','epoch'=>$settings['epoch'],'integrity_keys'=>'seals','authority'=>'current','management_guard'=>'manager','policy'=>$settings['policy']]],['db'=>$settings['pdo'],'seals'=>sealingKeys($settings['seals']),'current'=>$authority,'manager'=>$manager])->outbox();
}
function idempotency(array $settings):\SoSecurity\Idempotency\SqlExecutor
{
    $authority=static function(string $phase,\SoSecurity\Idempotency\Request $request)use($settings):bool{return $request->scope()===SCOPE&&$request->subject()===$settings['actor']&&$request->operation()==='orders.create'&&principal($settings,'orders_writer');};
    $management=static function(string $operation,string $scope,string $subject,string $action)use($settings):bool{return $scope===SCOPE&&$action==='orders.create'&&principal($settings,'outbox_admin')&&principal($settings,'orders_writer',$subject);};
    return new \SoSecurity\Idempotency\SqlExecutor($settings['pdo'],SITE,$settings['epoch'],sealingKeys($settings['idempotency_keys']),$authority,null,null,$management);
}
function produce(array $settings,string $key,string $reference,int $amount):array
{
    identifier($reference);if($amount<1||$amount>1000000){throw new ValidationException('Use bounded integer cents.','outbox_example.input');}
    if(!principal($settings,'orders_writer')||!budget($settings,'outbox.produce',$settings['actor'],60)){throw new SecurityException('Current writer and budget required.','outbox_example.denied');}
    $request=new \SoSecurity\Idempotency\Request(SCOPE,$settings['actor'],'orders.create',$key,'POST','/outbox/orders',json_encode(['reference'=>$reference,'amount'=>$amount]));$queue=outbox($settings);
    $result=idempotency($settings)->execute($request,static function(PDO $pdo,$request,string $execution)use($settings,$reference,$amount,$queue):\SoSecurity\Idempotency\Response{
        $q=$pdo->prepare("SELECT payload FROM outbox_example_orders WHERE subject=:actor AND reference_id=:reference AND typeof(payload)='blob' AND length(payload)<=8192");$q->execute(['actor'=>$settings['actor'],'reference'=>$reference]);$body=$q->fetchColumn();$q->closeCursor();
        if($body===false){
            $created=time();$data=['event_id'=>Message::identifier($execution,$created),'order_id'=>$execution,'reference'=>$reference,'subject'=>$settings['actor'],'amount'=>$amount,'created_at'=>$created,'tenant'=>SCOPE,'topic'=>'order.created'];$body=json_encode($data);
            $q=$pdo->prepare('INSERT INTO outbox_example_orders VALUES(:subject,:reference,:order,:amount,:created,:event,:body)');foreach(['subject'=>$settings['actor'],'reference'=>$reference,'order'=>$execution,'amount'=>$amount,'created'=>$created,'event'=>$data['event_id']] as $name=>$value){$q->bindValue(':'.$name,$value,is_int($value)?PDO::PARAM_INT:PDO::PARAM_STR);}$q->bindValue(':body',$body,PDO::PARAM_LOB);$q->execute();$q->closeCursor();
        }else{$data=event($body);if($data['amount']!==$amount){throw new SecurityException('Business reference content conflict.','outbox_example.conflict');}}
        $queue->enqueue(message($data,$body),$settings['actor']);return new \SoSecurity\Idempotency\Response(201,json_encode(['order_id'=>$data['order_id'],'event_id'=>$data['event_id'],'amount'=>$data['amount']]));
    });
    if($result===null){throw new SecurityException('Producer authority denied.','outbox_example.denied');}return ['replayed'=>$result->replayed(),'result'=>json_decode($result->response()->body(),true)];
}
function budget(array $settings,string $scope,string $subject,int $limit):bool
{
    return (new \SoSecurity\RateLimit\BudgetLimiter($settings['store'],new \SoSecurity\RateLimit\BudgetPolicy('fixed_window',$limit,60)))->consume($scope,$subject)->allowed();
}
function sendOnce(array $settings,int $after=0):array
{
    $queue=outbox($settings);$page=$queue->candidates(SCOPE,PRODUCER,$settings['actor'],20,$after);if($page===null){throw new SecurityException('Worker authority denied.','outbox_example.denied');}
    $sent=0;$failed=0;$claimed=0;$uri=\SoSecurity\Http\Uri::parse($settings['url']);
    foreach($page['records'] as $record){
        if(!in_array($record->state(),['pending','leased'],true)||!budget($settings,'outbox.send','receiver',60)){continue;}
        $claim=$queue->claimMessage(SCOPE,PRODUCER,$settings['actor'],$record->id());if($claim===null){continue;}++$claimed;
        $remaining=min($claim->status()->leaseUntil(),$claim->status()->deliverUntil())-time();if($remaining<2){throw new SecurityException('No send budget remains on the claim.','outbox_example.lease');}
        $keys=keyData($settings['wire_keys']);$id=$claim->status()->deliveryId();$body=$claim->message()->body();$stamp=(string)time();
        $headers=['Content-Type'=>'application/json','Webhook-Id'=>$id,'Webhook-Timestamp'=>$stamp,'Webhook-Signature'=>'v1,'.base64_encode(hash_hmac('sha256',$id.'.'.$stamp.'.'.$body,$keys['keys'][$keys['current']],true))];
        // A fresh status/authority check precedes network I/O. No network call occurs inside a SQL callback.
        $current=$queue->status(SCOPE,PRODUCER,$record->id(),$settings['actor']);if($current===null||$current->state()!=='leased'||$current->attempts()!==$claim->status()->attempts()||$current->leaseUntil()<=time()+1){throw new SecurityException('Claim is no longer usable.','outbox_example.lease');}
        $remaining=min($current->leaseUntil(),$current->deliverUntil())-time();if($remaining<2){throw new SecurityException('No send budget remains after current checks.','outbox_example.lease');}
        $client=new \SoSecurity\Http\Outbound\Client(new \SoSecurity\Http\Outbound\Policy(['hosts'=>[$uri->hostName()],'ports'=>[$uri->port()],'redirects'=>0,'request_bytes'=>8192,'response_bytes'=>768,'header_bytes'=>8192,'budget_ms'=>min($settings['transport_budget_ms'],($remaining-1)*1000)]));
        $accepted=false;$retryable=true;$failureCode='transport.unconfirmed';
        try{
            $response=$client->request('POST',$settings['url'],$headers,$body);$data=json_decode($response->body(),true,4);
            $accepted=$response->status()===200&&$response->values('content-type')===['application/json']&&is_array($data)&&count($data)===3&&substr_count($response->body(),':')===3&&($data['committed'] ?? null)===true&&($data['delivery_id'] ?? null)===$id&&($data['body_digest'] ?? null)===hash('sha256',$body);
            $retryable=!($response->status()>=400&&$response->status()<500&&$response->status()!==429);
            $failureCode=$response->status()===200?'transport.confirmation':($response->status()>=400&&$response->status()<500?'transport.rejected':'transport.remote');
        }catch(\SoSecurity\Exception\SecurityException $failure){
            // Only fixed bounded classifications are persisted; never response bytes, exception text or secrets.
            $reasons=['http.timeout'=>'transport.timeout','http.transport'=>'transport.unavailable','http.dns'=>'transport.dns','http.redirect_method'=>'transport.redirect','http.response_limit'=>'transport.response_limit','http.header_limit'=>'transport.header_limit','http.peer'=>'transport.peer'];$failureCode=$reasons[$failure->reason()] ?? 'transport.unconfirmed';
        }catch(ValidationException $failure){$failureCode='transport.policy';$retryable=false;}
        if($accepted){if(!$queue->acknowledge(SCOPE,PRODUCER,$settings['actor'],$claim->token())){throw new SecurityException('Delivery committed but acknowledgement was not recorded.','outbox_example.uncertain');}++$sent;}
        else{if(!$queue->fail(SCOPE,PRODUCER,$settings['actor'],$claim->token(),$failureCode,$retryable)){throw new SecurityException('Delivery result uncertain; recover the existing claim.','outbox_example.uncertain');}++$failed;}
    }
    return ['claimed'=>$claimed,'sent'=>$sent,'failed'=>$failed,'next_cursor'=>$page['next_cursor'],'complete'=>$page['complete']];
}
function endpoint(array $settings):\SoSecurity\Webhook\Endpoint {return new \SoSecurity\Webhook\Endpoint('orders',SCOPE,PUBLISHER,$settings['url'],'standard-hmac',['maximum_body'=>8192]);}
function mapped(string $body,string $delivery):\SoSecurity\Webhook\Message
{
    $data=event($body);if(!preg_match('/\A[a-f0-9]{64}\z/D',$delivery)){throw new ValidationException('Use a stable delivery ID.','outbox_example.input');}
    return new \SoSecurity\Webhook\Message($delivery,'order.created',$data['order_id'],['event_id'=>$data['event_id'],'subject'=>$data['subject']]);
}
function associated(array $settings,\SoSecurity\Webhook\Message $message):bool
{
    return authorityAllows($settings,['receiver_worker'],$message->context()['subject']);
}
function apply(PDO $pdo,\SoSecurity\Webhook\Message $message,string $body):bool
{
    $data=event($body);$q=$pdo->prepare('INSERT INTO outbox_example_effects VALUES(:publisher,:event,:delivery,:digest,:order,:subject,:amount) ON CONFLICT(publisher,event_id) DO NOTHING');$q->execute(['publisher'=>PUBLISHER,'event'=>$data['event_id'],'delivery'=>$message->id(),'digest'=>hash('sha256',$body),'order'=>$data['order_id'],'subject'=>$data['subject'],'amount'=>$data['amount']]);$inserted=$q->rowCount()===1;$q->closeCursor();
    $q=$pdo->prepare('SELECT 1 FROM outbox_example_effects WHERE publisher=:publisher AND event_id=:event AND delivery_id=:delivery AND body_digest=:digest AND order_id=:order AND subject=:subject AND amount=:amount');$q->execute(['publisher'=>PUBLISHER,'event'=>$data['event_id'],'delivery'=>$message->id(),'digest'=>hash('sha256',$body),'order'=>$data['order_id'],'subject'=>$data['subject'],'amount'=>$data['amount']]);$valid=$q->fetchColumn()!==false;$q->closeCursor();
    if(!$valid){throw new SecurityException('Receiver business event conflict.','outbox_example.conflict');}
    if($inserted){$q=$pdo->prepare('INSERT INTO outbox_example_projection VALUES(:subject,:order,:amount,1)');$q->execute(['subject'=>$data['subject'],'order'=>$data['order_id'],'amount'=>$data['amount']]);$q->closeCursor();}return true;
}
function receive(array $settings,\SoSecurity\Webhook\Request $request,callable $requestGuard):array
{
    $endpoint=endpoint($settings);$verifier=new \SoSecurity\Webhook\Verifier($endpoint,static function()use($settings,$endpoint){$keys=keyData($settings['wire_keys']);return new \SoSecurity\Webhook\KeySet($endpoint,$keys['keys']);},$requestGuard);
    $proof=$verifier->verify($request);if($proof===null){throw new SecurityException('Current publisher signature required.','outbox_example.denied');}mapped($request->body(),$proof->messageId());
    if(!budget($settings,'outbox.publisher',PUBLISHER,120)){throw new SecurityException('Publisher budget exhausted.','outbox_example.rate');}
    return receiverLocked($settings,static function()use($settings,$request,$endpoint,$verifier,$proof):array{
    $initial=receiverCurrent($settings);$plan=receiverPlan($settings,$initial,$request->body(),$proof->messageId());$allowedRoots=[$initial];
    $keys=sealingKeys($settings['seals']);$association=static function($endpoint,$message)use($settings,&$allowedRoots):bool{
        $actual=receiverRead($settings['pdo'],'root');$found=false;foreach($allowedRoots as $root){if($root===$actual){receiverVerifyRoot($settings,$root);$found=true;break;}}return $found&&associated($settings,$message);
    };
    $inbox=new \SoSecurity\Webhook\SqlInbox($settings['pdo'],SITE,$verifier,$keys,$association);
    $receipt=$inbox->accept($request,static function($verified){return mapped($verified->body(),$verified->messageId());});if($receipt===null){throw new SecurityException('Current receiving association required.','outbox_example.denied');}
    $worker=$settings['actor'];$processor=new \SoSecurity\Webhook\SqlProcessor($settings['pdo'],SITE,$endpoint,$keys,static function(string $body,$endpoint,string $receipt,array $metadata){return mapped($body,$metadata['message_id']);},$association,static function(string $action,$endpoint,string $receipt,string $actor)use($settings):bool{return $actor===$settings['actor']&&principal($settings,'receiver_worker');});
    if($plan!==null){
        $claim=$processor->claim($receipt->id(),$worker);if($claim===null){throw new SecurityException('Receiving work is not confirmed.','outbox_example.uncertain');}
        receiverSaveWitness($settings,$plan,'prepared');$allowedRoots[]=$plan['current'];
        $status=$processor->execute($worker,$claim->token(),static function()use($settings,$plan):bool{receiverApplyPlan($settings,$plan);return true;});
        if($status===null||$status->status()!=='succeeded'){throw new SecurityException('Receiving work is not confirmed.','outbox_example.uncertain');}
        receiverVerifyRoot($settings,$plan['current']);receiverSaveWitness($settings,$plan,'committed');
    }
    // Recheck the independent business ledger and current association before reporting a committed effect.
    $message=mapped($request->body(),$proof->messageId());$data=event($request->body());$q=$settings['pdo']->prepare('SELECT 1 FROM outbox_example_effects WHERE publisher=:publisher AND event_id=:event AND delivery_id=:delivery AND body_digest=:digest');$q->execute(['publisher'=>PUBLISHER,'event'=>$data['event_id'],'delivery'=>$message->id(),'digest'=>hash('sha256',$request->body())]);$valid=$q->fetchColumn()!==false;$q->closeCursor();
    receiverCurrent($settings);if(!$valid||!associated($settings,$message)||$verifier->verify($request)===null){throw new SecurityException('Receiving confirmation is unavailable.','outbox_example.uncertain');}
    return ['committed'=>true,'delivery_id'=>$message->id(),'body_digest'=>hash('sha256',$request->body())];
    });
}
