<?php
declare(strict_types=1);
namespace SoSecurity\Examples\WebhookBusiness;

use PDO;
use SoSecurity\Webhook\Endpoint;
use SoSecurity\Webhook\Message;
use SoSecurity\Webhook\ProcessingStatus;

// Pure host adapter definitions. Importing this file performs no I/O or initialization.
const SCOPE='webhook-example';
const ACCOUNT='publisher-example';

function map(string $raw,Endpoint $endpoint,string $messageId):?Message
{
    $input=json_decode($raw,true,8);
    if(!is_array($input)||count($input)!==6||array_diff(array_keys($input),['id','type','resource','version','tenant','account'])){return null;}
    foreach($input as $value){if(!is_string($value)||$value===''||strlen($value)>256){return null;}}
    if($endpoint->scope()!==SCOPE||$endpoint->account()!==ACCOUNT||$input['id']!==$messageId||$input['tenant']!==SCOPE||$input['account']!==ACCOUNT||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$input['resource'])||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$input['version'])||$input['type']!=='document.changed'){return null;}
    return new Message($input['id'],$input['type'],$input['resource'],['version'=>$input['version'],'tenant'=>$input['tenant'],'account'=>$input['account']]);
}

function associated(PDO $pdo,Endpoint $endpoint,Message $message):bool
{
    $context=$message->context();
    if($endpoint->scope()!==SCOPE||$endpoint->account()!==ACCOUNT||($context['tenant'] ?? null)!==SCOPE||($context['account'] ?? null)!==ACCOUNT||$message->type()!=='document.changed'){return false;}
    $query=$pdo->prepare('SELECT 1 FROM webhook_documents WHERE tenant=:tenant AND account=:account AND id=:id AND version=:version AND enabled=1');
    $query->execute(['tenant'=>SCOPE,'account'=>ACCOUNT,'id'=>$message->resource(),'version'=>$context['version'] ?? '']);
    return $query->fetchColumn()!==false;
}

/** Run only inside SqlProcessor's transaction, using its PDO. No external side effects or transaction control. */
function apply(PDO $pdo,Message $message,string $raw,ProcessingStatus $status):bool
{
    $context=$message->context();
    if(($context['tenant'] ?? null)!==SCOPE||($context['account'] ?? null)!==ACCOUNT||$message->type()!=='document.changed'){return false;}
    $event=hash('sha256',$message->id());$digest=hash('sha256',$raw);
    $query=$pdo->prepare('SELECT body_digest,resource_id,resource_version FROM webhook_example_effects WHERE tenant=:tenant AND account=:account AND event_key=:event');
    $query->execute(['tenant'=>SCOPE,'account'=>ACCOUNT,'event'=>$event]);$existing=$query->fetch(PDO::FETCH_ASSOC);
    if(is_array($existing)){return hash_equals($digest,$existing['body_digest'])&&$existing['resource_id']===$message->resource()&&$existing['resource_version']===$context['version'];}
    $query=$pdo->prepare('INSERT INTO webhook_example_effects(tenant,account,event_key,body_digest,resource_id,resource_version,receipt_id) VALUES(:tenant,:account,:event,:digest,:resource,:version,:receipt)');
    $query->execute(['tenant'=>SCOPE,'account'=>ACCOUNT,'event'=>$event,'digest'=>$digest,'resource'=>$message->resource(),'version'=>$context['version'],'receipt'=>$status->receiptId()]);
    $query=$pdo->prepare('SELECT event_count FROM webhook_example_projection WHERE tenant=:tenant AND account=:account AND resource_id=:resource');
    $query->execute(['tenant'=>SCOPE,'account'=>ACCOUNT,'resource'=>$message->resource()]);$count=$query->fetchColumn();
    $query=$pdo->prepare($count===false?'INSERT INTO webhook_example_projection(tenant,account,resource_id,resource_version,event_count,last_event) VALUES(:tenant,:account,:resource,:version,1,:event)':'UPDATE webhook_example_projection SET resource_version=:version,event_count=event_count+1,last_event=:event WHERE tenant=:tenant AND account=:account AND resource_id=:resource AND event_count BETWEEN 1 AND 999999999');
    $query->execute(['tenant'=>SCOPE,'account'=>ACCOUNT,'resource'=>$message->resource(),'version'=>$context['version'],'event'=>$event]);
    return $query->rowCount()===1;
}
