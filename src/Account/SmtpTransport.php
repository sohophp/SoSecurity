<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Http\Uri;
use SoSecurity\Support\Deadline;
use SoSecurity\Support\Guard;
use SoSecurity\Exception\SecurityException;

/** One bounded pinned SMTP submission. Fixed private endpoint, mandatory verified TLS except an explicit private Unix relay. */
final class SmtpTransport implements MailTransport
{
    private $settings;
    public function __construct(string $name,string $host,int $port,string $address,string $mode='starttls',?array $credentials=null,?string $caFile=null,?string $unixSocket=null,bool $allowSmtpUtf8=false,string $clientName='localhost')
    {
        Guard::label($name);$canonical=Uri::host($host);if(Uri::host($clientName)!==$clientName){throw new ConfigurationException('Use a fixed canonical SMTP client name.','configuration.account_smtp');}
        if($host!==$canonical||$port<1||$port>65535||!in_array($mode,['starttls','tls','unix'],true)||($mode==='unix')!==($unixSocket!==null)||($mode!=='unix'&&filter_var($address,FILTER_VALIDATE_IP)===false)){throw new ConfigurationException('Configure a fixed canonical SMTP endpoint, pinned address and explicit TLS mode.','configuration.account_smtp');}
        if($credentials!==null){$keys=array_keys($credentials);sort($keys);if($keys!==['password','username']||!is_string($credentials['username'])||!is_string($credentials['password'])||$credentials['username']===''||strlen($credentials['username'])>256||strlen($credentials['password'])>1024||preg_match('/[\x00-\x1f\x7f]/',$credentials['username'])||strpos($credentials['password'],"\0")!==false||$mode==='unix'){throw new ConfigurationException('Use bounded private SMTP credentials only with verified TLS.','configuration.account_smtp');}$credentials=['username'=>$credentials['username'],'password'=>$credentials['password']];}
        if($caFile!==null&&($mode==='unix'||$caFile===''||strlen($caFile)>4096||strpos($caFile,"\0")!==false)){throw new ConfigurationException('Use a fixed private SMTP CA file.','configuration.account_smtp');}
        if($unixSocket!==null&&($unixSocket===''||strlen($unixSocket)>100||$unixSocket[0]!=='/'||strpos($unixSocket,"\0")!==false)){throw new ConfigurationException('Use a short absolute private Unix SMTP socket path.','configuration.account_smtp');}
        $this->settings=static function()use($name,$host,$port,$address,$mode,$credentials,$caFile,$unixSocket,$allowSmtpUtf8,$clientName):array{return [$name,$host,$port,$address,$mode,$credentials,$caFile,$unixSocket,$allowSmtpUtf8,$clientName];};
    }
    public function name():string {return ($this->settings)()[0];}
    private static function unix(string $path):void
    {
        $directory=dirname($path);$s=@lstat($path);$d=@lstat($directory);
        if(!function_exists('posix_geteuid')||!is_array($s)||!is_array($d)||realpath($directory)!==$directory||is_link($path)||($s['mode']&0170000)!==0140000||($d['mode']&0170000)!==0040000||($d['mode']&0077)!==0||$s['uid']!==posix_geteuid()||$d['uid']!==posix_geteuid()){throw new ConfigurationException('Unix SMTP requires a current-user private real directory and socket.','configuration.account_smtp_socket');}
    }
    /** Wait for readiness without extending the single overall deadline. */
    private static function ready($stream,Deadline $deadline,bool $write=false):void
    {
        $deadline->check('smtp.timeout');$remaining=$deadline->remaining();$seconds=(int)$remaining;$microseconds=(int)(($remaining-$seconds)*1000000);
        $reads=$write?[]:[$stream];$writes=$write?[$stream]:[];$except=[];
        $ready=@stream_select($reads,$writes,$except,$seconds,$microseconds);$deadline->check('smtp.timeout');
        if($ready===false){throw new SecurityException('SMTP stream unavailable.','smtp.unavailable');}
    }
    private static function write($stream,string $bytes,Deadline $deadline,?callable $gate=null,?bool &$started=null):void
    {
        $offset=0;$size=strlen($bytes);
        while($offset<$size){
            self::ready($stream,$deadline,true);
            if($gate!==null){try{$allowed=$gate()===true;}catch(\Throwable $error){$allowed=false;}if(!$allowed){throw new SecurityException('Current mail authority refused.','smtp.guard_refused');}}
            $deadline->check('smtp.timeout');if($gate!==null){$started=true;}$written=@fwrite($stream,substr($bytes,$offset,4096));
            if($written===false||($written===0&&feof($stream))){throw new SecurityException('SMTP write failed.','smtp.unavailable');}
            if($written>0){$offset+=$written;if($gate!==null){$started=true;}}
        }
    }
    /** Never buffer more than 512 reply bytes, including CRLF; total replies are limited to 8192. */
    private static function reply($stream,Deadline $deadline,int &$total):array
    {
        $group=null;$lines=[];
        do{
            $line='';
            while(substr($line,-2)!=="\r\n"){
                if(strlen($line)>=512||$total>=8192){throw new SecurityException('SMTP reply exceeded its bound.','smtp.response_invalid');}
                self::ready($stream,$deadline);$byte=@stream_get_contents($stream,1);
                if($byte===false||($byte===''&&feof($stream))){throw new SecurityException('SMTP reply unavailable.','smtp.unconfirmed');}
                $line.=$byte;$total+=strlen($byte);
            }
            if(!preg_match('/\A([2-5][0-9]{2})(?:([- ])([^\x00-\x08\x0a-\x1f\x7f]*))?\r\n\z/D',$line,$match)){
                throw new SecurityException('Malformed SMTP reply.','smtp.response_invalid');
            }
            $code=(int)$match[1];if($group!==null&&$group!==$code){throw new SecurityException('Inconsistent SMTP reply.','smtp.response_invalid');}
            $group=$code;$lines[]=$match[3] ?? '';
        }while(($match[2] ?? ' ')==='-');
        return [$code,$lines];
    }
    private static function tls($stream,Deadline $deadline):void
    {
        $method=STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;if(defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')){$method|=constant('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT');}
        if(!stream_context_set_option($stream,'ssl','crypto_method',$method)){throw new SecurityException('Cannot set SMTP TLS policy.','smtp.tls_failed');}
        do{$deadline->check('smtp.timeout');$enabled=@stream_socket_enable_crypto($stream,true);if($enabled===false){throw new SecurityException('Verified SMTP TLS failed.','smtp.tls_failed');}if($enabled===0){self::ready($stream,$deadline);}}while($enabled!==true);
        $deadline->check('smtp.timeout');
    }
    private static function capabilities(array $lines):array
    {
        $result=[];foreach($lines as $line){if(preg_match('/\A([A-Za-z0-9][A-Za-z0-9-]*)(?:[ \t]+(.*))?\z/D',$line,$m)){$result[strtoupper($m[1])]=strtoupper($m[2] ?? '');}}return $result;
    }
    private static function command($stream,string $command,Deadline $deadline,int &$total):array
    {
        self::write($stream,$command."\r\n",$deadline);return self::reply($stream,$deadline,$total);
    }
    public function send(MailMessage $message,int $milliseconds,callable $gate):MailResult
    {
        if($milliseconds<1||$milliseconds>10000){throw new ConfigurationException('Use a 1-10000ms SMTP submission budget.','configuration.account_smtp');}
        list(,$host,$port,$address,$mode,$credentials,$caFile,$socket,$allowUtf8,$clientName)=($this->settings)();
        if($mode!=='unix'&&(!extension_loaded('openssl')||!defined('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT'))){throw new DependencyException('SMTP requires OpenSSL with TLS 1.2.','dependency.smtp');}
        if($message->requiresSmtpUtf8()&&!$allowUtf8){return new MailResult('rejected','smtp.smtputf8_required');}
        if($mode==='unix'){self::unix($socket);}
        if($caFile!==null&&(!is_file($caFile)||is_link($caFile)||!is_readable($caFile)||realpath($caFile)!==$caFile)){throw new ConfigurationException('SMTP CA file unavailable.','configuration.account_smtp');}
        $deadline=new Deadline($milliseconds);$stream=null;$started=false;$total=0;$code=0;
        try{
            $ssl=['verify_peer'=>true,'verify_peer_name'=>true,'allow_self_signed'=>false,'peer_name'=>$host,'SNI_enabled'=>true,'disable_compression'=>true];if($caFile!==null){$ssl['cafile']=$caFile;}
            $context=stream_context_create(['ssl'=>$ssl]);$target=$mode==='unix'?'unix://'.$socket:'tcp://'.(strpos($address,':')===false?$address:'['.$address.']').':'.$port;
            $number=0;$detail='';$stream=@stream_socket_client($target,$number,$detail,max(0.001,$deadline->remaining()),STREAM_CLIENT_CONNECT,$context);
            $deadline->check('smtp.timeout');if(!is_resource($stream)){throw new SecurityException('SMTP connection unavailable.','smtp.unavailable');}
            if(!stream_set_blocking($stream,false)){throw new SecurityException('Cannot bound SMTP I/O.','smtp.unavailable');}
            if($mode==='tls'){self::tls($stream,$deadline);}
            list($code)=self::reply($stream,$deadline,$total);if($code!==220){return new MailResult('rejected','smtp.rejected',$code<500);}
            list($code,$lines)=self::command($stream,'EHLO '.$clientName,$deadline,$total);if($code!==250){return new MailResult('rejected','smtp.rejected',$code<500);}$caps=self::capabilities($lines);
            if($mode==='starttls'){
                if(!isset($caps['STARTTLS'])){return new MailResult('rejected','smtp.tls_required');}
                list($code)=self::command($stream,'STARTTLS',$deadline,$total);if($code!==220){return new MailResult('rejected','smtp.tls_required');}
                self::tls($stream,$deadline);
                list($code,$lines)=self::command($stream,'EHLO '.$clientName,$deadline,$total);if($code!==250){return new MailResult('rejected','smtp.rejected',$code<500);}$caps=self::capabilities($lines);
            }
            if($message->requiresSmtpUtf8()&&!isset($caps['SMTPUTF8'])){return new MailResult('rejected','smtp.smtputf8_required');}
            if($credentials!==null){
                if(!isset($caps['AUTH'])||!in_array('PLAIN',preg_split('/[ \t]+/',$caps['AUTH']),true)){return new MailResult('rejected','smtp.authentication_required');}
                list($code)=self::command($stream,'AUTH PLAIN',$deadline,$total);if($code!==334){return new MailResult('rejected','smtp.authentication_failed',$code<500);}
                list($code)=self::command($stream,base64_encode("\0".$credentials['username']."\0".$credentials['password']),$deadline,$total);if($code!==235){return new MailResult('rejected','smtp.authentication_failed',$code<500);}
            }
            foreach(['MAIL FROM:<'.$message->sender()->value().'>'.($message->requiresSmtpUtf8()?' SMTPUTF8':''),'RCPT TO:<'.$message->recipient()->value().'>','DATA'] as $command){
                list($code)=self::command($stream,$command,$deadline,$total);if(!in_array($code,$command==='DATA'?[354]:($command[0]==='R'?[250,251]:[250]),true)){return new MailResult('rejected','smtp.rejected',$code<500);}
            }
            // MailMessage builds only fixed headers and base64 text, so no line starts with a dot.
            self::write($stream,$message->wire(),$deadline,$gate,$started);self::write($stream,".\r\n",$deadline,$gate,$started);
            list($code)=self::reply($stream,$deadline,$total);
            if($code===250){return new MailResult('accepted','smtp.accepted');}
            if($code>=400){return new MailResult('rejected','smtp.rejected',$code<500);}
            return new MailResult('unknown','smtp.unconfirmed');
        }catch(\Throwable $error){
            $safe=$error instanceof SecurityException?$error->reason():'smtp.unavailable';
            if(!in_array($safe,['smtp.timeout','smtp.response_invalid','smtp.unavailable','smtp.unconfirmed','smtp.guard_refused','smtp.tls_failed'],true)){$safe='smtp.unavailable';}
            return new MailResult($started?'unknown':'rejected',$safe,!$started&&!in_array($safe,['smtp.guard_refused','smtp.response_invalid','smtp.tls_failed'],true));
        }finally{if(is_resource($stream)){fclose($stream);}}
    }
    public function __debugInfo():array {return ['smtp_transport'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Do not serialize SMTP secrets.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload private SMTP configuration.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('SMTP transport is immutable.','configuration.immutable');}
}
