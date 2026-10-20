<?php
declare(strict_types=1);
namespace SoSecurity\Webhook;
use SoSecurity\Exception\ConfigurationException;

/** Inert bounded status; not execution authority. No payload, worker secret or result body. */
final class ProcessingStatus
{
    private $data;
    public function __construct(string $receiptId,string $status,int $attempt,int $totalAttempts,int $manualRetries,int $revision,int $availableAt,int $leaseUntil,int $updatedAt,string $errorCode='')
    {
        if(!preg_match('/\A[a-f0-9]{32}\z/D',$receiptId)||!in_array($status,['ready','leased','retry','succeeded','dead'],true)||$attempt<0||$attempt>20||$totalAttempts<$attempt||$totalAttempts>100||$manualRetries<0||$manualRetries>8||$revision<1||$availableAt<0||$leaseUntil<0||$updatedAt<0||($errorCode!==''&&!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$errorCode))){throw new ConfigurationException('Invalid processing metadata.','configuration.webhook_processing');}
        $this->data=['receipt_id'=>$receiptId,'status'=>$status,'attempt'=>$attempt,'total_attempts'=>$totalAttempts,'manual_retries'=>$manualRetries,'revision'=>$revision,'available_at'=>$availableAt,'lease_until'=>$leaseUntil,'updated_at'=>$updatedAt,'error_code'=>$errorCode];
    }
    public function toArray():array {return $this->data;}
    public function receiptId():string {return $this->data['receipt_id'];}
    public function status():string {return $this->data['status'];}
    public function attempt():int {return $this->data['attempt'];}
    public function revision():int {return $this->data['revision'];}
    public function availableAt():int {return $this->data['available_at'];}
    public function leaseUntil():int {return $this->data['lease_until'];}
    public function errorCode():string {return $this->data['error_code'];}
    public function __set(string $name,$value):void {throw new ConfigurationException('Processing metadata is immutable.','configuration.immutable');}
}
