<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
/** SMTP submission is not mailbox delivery. unknown means content may already have been accepted. */
final class MailResult
{
    private $state;
    private $code;
    private $retryable;
    public function __construct(string $state,string $code,bool $retryable=false)
    {
        if(!in_array($state,['accepted','rejected','unknown'],true)||!preg_match('/\A[a-z][a-z0-9_.-]{0,63}\z/D',$code)||($state==='accepted'&&($retryable||$code!=='smtp.accepted'))){throw new ConfigurationException('Use fixed bounded SMTP submission outcomes.','configuration.account_mail_result');}$this->state=$state;$this->code=$code;$this->retryable=$retryable;
    }
    public function state():string {return $this->state;}
    public function code():string {return $this->code;}
    public function retryable():bool {return $this->retryable;}
    public function __set(string $name,$value):void {throw new ConfigurationException('Mail results are immutable.','configuration.immutable');}
}
