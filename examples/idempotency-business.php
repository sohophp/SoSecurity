<?php
declare(strict_types=1);
namespace SoSecurity\Examples\Idempotency;

use PDO;
use SoSecurity\Api\ApiKeys;
use SoSecurity\Api\Identity;
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\Resource;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;
use SoSecurity\Idempotency\Request;
use SoSecurity\Idempotency\Response;
use SoSecurity\Security;
use SoSecurity\Storage\FileStore;
use SoSecurity\Support\HmacKeys;

const SCOPE='idempotency-example';
const SITE='idempotency-native-example';

// Importing this adapter does not read configuration, open a database, create a session or write data.
function identifier($value):string
{
    if(!is_string($value)||!preg_match('/\A[A-Za-z0-9_-]{1,64}\z/D',$value)){throw new ValidationException('Invalid bounded identifier.','idempotency_example.input');}return $value;
}
function privateFile(string $name,string $webRoot,int $maximum=0):string
{
    $path=getenv($name);$real=is_string($path)?realpath($path):false;
    if($real===false||$path!==$real||!is_file($real)||is_link($path)||(fileperms($real)&0077)!==0||$real===$webRoot||strpos($real,rtrim($webRoot,'/').'/')===0||($maximum>0&&filesize($real)>$maximum)){throw new \RuntimeException('Configure a canonical private file outside the web root.');}return $real;
}
function privateStore(string $webRoot):FileStore
{
    $web=realpath($webRoot);$directory=getenv('SOSECURITY_IDEMPOTENCY_EXAMPLE_STORAGE');$root=is_string($directory)?realpath($directory):false;
    if($web===false||$web!==rtrim($webRoot,'/')||$root===false||$root!==rtrim($directory,'/')||$root===$web||strpos($root,rtrim($web,'/').'/')===0){throw new \RuntimeException('Configure private state outside the actual web root.');}
    return new FileStore($root,SCOPE);
}
function settings(string $webRoot,?FileStore $store=null):array
{
    $web=realpath($webRoot);if($web===false||$web!==rtrim($webRoot,'/')){throw new \RuntimeException('Configure the canonical actual web root.');}
    $store=$store ?? privateStore($web);$database=privateFile('SOSECURITY_IDEMPOTENCY_EXAMPLE_DATABASE',$web);
    $json=file_get_contents(privateFile('SOSECURITY_IDEMPOTENCY_EXAMPLE_KEYS',$web,16384),false,null,0,16385);$data=is_string($json)&&strlen($json)<=16384?json_decode($json,true,5):null;
    if(!is_array($data)||count($data)!==2||!is_string($data['current'] ?? null)||!is_array($data['keys'] ?? null)){throw new \RuntimeException('Invalid private integrity key configuration.');}$keys=[];
    foreach($data['keys'] as $name=>$encoded){if(!is_string($encoded)||!is_string($decoded=base64_decode($encoded,true))||base64_encode($decoded)!==$encoded){throw new \RuntimeException('Invalid private key encoding.');}$keys[$name]=$decoded;}
    $epoch=getenv('SOSECURITY_IDEMPOTENCY_EXAMPLE_EPOCH');if(!is_string($epoch)||!preg_match('/\A[a-f0-9]{64}\z/D',$epoch)){throw new \RuntimeException('Configure an external deployment epoch.');}
    $policy=[];foreach(['TTL'=>['ttl',31536000],'CAPACITY'=>['maximum_entries',100000]] as $suffix=>$definition){$value=getenv('SOSECURITY_IDEMPOTENCY_EXAMPLE_'.$suffix);if($value!==false){if(!preg_match('/\A[1-9][0-9]{0,7}\z/D',$value)||(int)$value>$definition[1]){throw new \RuntimeException('Invalid bounded policy configuration.');}$policy[$definition[0]]=(int)$value;}}
    $pdo=new PDO('sqlite:'.$database,null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>1]);
    return ['pdo'=>$pdo,'store'=>$store,'keys'=>new HmacKeys($data['current'],$keys),'epoch'=>$epoch,'policy'=>$policy];
}
function account(PDO $pdo,string $scope,string $subject):?Account
{
    if($scope!==SCOPE){return null;}identifier($subject);
    $sql='SELECT version,enabled,roles FROM idempotency_example_accounts WHERE tenant=:tenant AND subject=:subject AND length(CAST(version AS BLOB))<=64 AND length(CAST(roles AS BLOB))<=4096';
    if($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql'&&$pdo->inTransaction()){$sql.=' FOR UPDATE';}
    $q=$pdo->prepare($sql);$q->execute(['tenant'=>$scope,'subject'=>$subject]);$row=$q->fetch(PDO::FETCH_ASSOC);if(!is_array($row)){return null;}
    identifier($row['version']);$roles=is_string($row['roles'])?json_decode($row['roles'],true,4):null;
    if(!in_array((string)$row['enabled'],['0','1'],true)||!is_array($roles)||array_values($roles)!==$roles){throw new \RuntimeException('Invalid current account source.');}
    return new Account($scope,$subject,$row['version'],(string)$row['enabled']==='1',$roles);
}
function authenticated(PDO $pdo,ApiKeys $api,$header):?array
{
    $proof=$api->fromAuthorization($header,'orders:create');if($proof===null){return null;}$parts=explode('@',$proof->subject());if(count($parts)!==2){return null;}
    $actor=account($pdo,SCOPE,identifier($parts[0]));return $actor!==null&&$actor->enabled()&&hash_equals($actor->version(),$parts[1])?[$proof,$actor]:null;
}
function payload(string $body):array
{
    $data=strlen($body)<=8192?json_decode($body,true,4):null;
    if(!is_array($data)||count($data)!==2||!is_int($data['amount'] ?? null)||$data['amount']<1||$data['amount']>1000000){throw new ValidationException('Provide only a reference and bounded integer amount.','idempotency_example.input');}identifier($data['reference'] ?? null);
    // For this two-scalar schema, valid identifier/number values and member names cannot contain colons.
    // Exactly two separators also rejects overwritten members and escaped-name aliases hidden by json_decode().
    if(substr_count($body,':')!==2){throw new ValidationException('Duplicate JSON members are not supported.','idempotency_example.input');}return $data;
}
function request(Identity $proof,Account $actor,array $server,string $body):Request
{
    payload($body);if(!$proof->allows('orders:create')||$proof->subject()!==$actor->subject().'@'.$actor->version()){throw new SecurityException('Current bearer identity required.','idempotency_example.denied');}
    return new Request(SCOPE,$actor->subject(),'orders.create',$server['HTTP_IDEMPOTENCY_KEY'] ?? '',$server['REQUEST_METHOD'] ?? '',$server['REQUEST_URI'] ?? '',$body,['content_type'=>'application/json']);
}
function factory(array $settings,?callable $authority=null,?callable $management=null):Security
{
    $services=['db'=>$settings['pdo'],'integrity'=>$settings['keys'],'current'=>$authority ?? static function():bool{return false;}];if($management!==null){$services['manager']=$management;}
    return Security::fromArray(['site'=>SITE,'idempotency'=>['connection'=>'db','epoch'=>$settings['epoch'],'integrity_keys'=>'integrity','authority'=>'current','management_guard'=>$management===null?null:'manager','policy'=>$settings['policy']]],$services);
}
function authority(PDO $pdo,ApiKeys $api,$header,Identity $proof,Account $actor):callable
{
    $source=new CallbackIdentityProvider(static function(){return null;},static function(string $scope,string $subject)use($pdo){return account($pdo,$scope,$subject);});
    $authorizer=new Authorizer($source,new RolePolicy(['orders.create'=>['type'=>'order_owner','roles'=>['orders_writer'],'fields'=>['reference','amount'],'owner_attribute'=>'owner']]));
    return static function(string $phase,Request $request,array $metadata)use($pdo,$api,$header,$proof,$actor,$authorizer):bool{
        $fresh=authenticated($pdo,$api,$header);if($fresh===null||$fresh[0]->id()!==$proof->id()||$fresh[1]->fingerprint()!==$actor->fingerprint()||$request->scope()!==SCOPE||$request->subject()!==$actor->subject()||$request->operation()!=='orders.create'){return false;}
        $resource=new Resource(SCOPE,'order_owner',$actor->subject(),$actor->version(),['owner'=>$actor->subject()]);if(!$authorizer->decide(SCOPE,$actor,'orders.create',$resource,['reference','amount'])->allowed()){return false;}
        if(isset($metadata['execution_id'])&&$phase!=='execute'){
            // Authorize the authenticated stored execution, even when the incoming parameters conflict.
            // The core then compares request fingerprints before it can return any cached bytes.
            $q=$pdo->prepare('SELECT 1 FROM idempotency_example_executions e INNER JOIN idempotency_example_orders o ON o.tenant=e.tenant AND o.subject=e.subject AND o.reference_id=e.reference_id AND o.order_id=e.order_id WHERE e.execution_id=:execution AND e.tenant=:tenant AND e.subject=:subject AND e.fingerprint=:fingerprint');$q->execute(['execution'=>$metadata['execution_id'],'tenant'=>SCOPE,'subject'=>$actor->subject(),'fingerprint'=>$metadata['fingerprint']]);if($q->fetchColumn()===false){return false;}
        }
        $current=$api->fromAuthorization($header,'orders:create');return $current!==null&&$current->id()===$proof->id()&&$current->subject()===$proof->subject();
    };
}
function createOrder(PDO $pdo,Request $request,string $execution):Response
{
    $data=payload($request->body());$q=$pdo->prepare('SELECT order_id,amount FROM idempotency_example_orders WHERE tenant=:tenant AND subject=:subject AND reference_id=:reference AND length(order_id)=32 AND amount BETWEEN 1 AND 1000000');$q->execute(['tenant'=>$request->scope(),'subject'=>$request->subject(),'reference'=>$data['reference']]);$order=$q->fetch(PDO::FETCH_ASSOC);
    if(!is_array($order)){$order=['order_id'=>$execution,'amount'=>$data['amount']];$q=$pdo->prepare('INSERT INTO idempotency_example_orders VALUES(:tenant,:subject,:reference,:order,:amount,:created)');$q->execute(['tenant'=>$request->scope(),'subject'=>$request->subject(),'reference'=>$data['reference'],'order'=>$execution,'amount'=>$data['amount'],'created'=>time()]);}
    $q=$pdo->prepare('INSERT INTO idempotency_example_executions VALUES(:execution,:tenant,:subject,:reference,:amount,:fingerprint,:order)');$q->execute(['execution'=>$execution,'tenant'=>$request->scope(),'subject'=>$request->subject(),'reference'=>$data['reference'],'amount'=>$data['amount'],'fingerprint'=>$request->fingerprint(),'order'=>$order['order_id']]);
    if((string)$order['amount']!==(string)$data['amount']){return new Response(409,json_encode(['error'=>'order.reference_conflict']));}
    return new Response(201,json_encode(['order_id'=>$order['order_id'],'reference'=>$data['reference'],'amount'=>$data['amount']]));
}
