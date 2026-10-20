<?php
declare(strict_types=1);
namespace SoSecurity\Account;

use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\ValidationException;

/** A bounded mailbox value, never proof that its owner has been verified. */
final class Address
{
    // An opaque closure also avoids var_export() expanding the private mailbox string.
    private $value;
    private $smtpUtf8;

    public function __construct(string $value,bool $allowSmtpUtf8=false)
    {
        if($value===''||strlen($value)>1024||preg_match('/[\x00-\x20\x7f]/',$value)||preg_match('//u',$value)!==1){self::invalid();}
        if(!function_exists('filter_var')||!defined('FILTER_VALIDATE_DOMAIN')||!defined('FILTER_FLAG_EMAIL_UNICODE')){throw new DependencyException('Mailbox validation requires ext-filter.','dependency.filter');}
        $at=strrpos($value,'@');
        if($at===false){self::invalid();}
        $local=substr($value,0,$at);$domain=substr($value,$at+1);
        if($local===''||strlen($local)>64||$domain===''||strpos($local,'"')!==false){self::invalid();}
        $this->smtpUtf8=preg_match('/[^\x00-\x7f]/',$local)===1;
        if($this->smtpUtf8&&!$allowSmtpUtf8){self::invalid();}
        // Unicode and A-label domains share one non-transitional UTS #46 contract.
        if(preg_match('/[^\x00-\x7f]/',$domain)||preg_match('/(?:\A|\.)xn--/i',$domain)){
            if(!function_exists('idn_to_ascii')||!defined('INTL_IDNA_VARIANT_UTS46')){throw new DependencyException('International domains require ext-intl UTS #46.','dependency.intl_idna');}
            $info=[];
            $domain=idn_to_ascii($domain,IDNA_USE_STD3_RULES|IDNA_CHECK_BIDI|IDNA_CHECK_CONTEXTJ|IDNA_NONTRANSITIONAL_TO_ASCII,INTL_IDNA_VARIANT_UTS46,$info);
            if(!is_string($domain)||!isset($info['errors'])||$info['errors']!==0){self::invalid();}
        }
        $domain=strtolower($domain);
        // Account notifications accept DNS hostnames, not address literals or display-name/header syntax.
        if(strlen($domain)>253||strpos($domain,'.')===false||substr($domain,-1)==='.'||filter_var($domain,FILTER_VALIDATE_DOMAIN,FILTER_FLAG_HOSTNAME)===false){self::invalid();}
        $canonical=$local.'@'.$domain;
        if(strlen($canonical)>254||filter_var($canonical,FILTER_VALIDATE_EMAIL,$allowSmtpUtf8?FILTER_FLAG_EMAIL_UNICODE:0)===false){self::invalid();}
        $this->value=static function()use($canonical):string{return $canonical;};
    }
    /** @return never */
    private static function invalid():void {throw new ValidationException('Use a bounded mailbox address supported by the configured transport.','account.address');}
    /** Preserve the local part exactly; no provider-specific dot/plus/case rewriting. */
    public function value():string {return ($this->value)();}
    public function requiresSmtpUtf8():bool {return $this->smtpUtf8;}
    public function equals(Address $other):bool {return hash_equals($this->value(),$other->value());}
    public function __debugInfo():array {return ['address'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Reload mailbox values from trusted account state.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Mailbox objects cannot be deserialized.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Mailbox values are immutable.','configuration.immutable');}
}
