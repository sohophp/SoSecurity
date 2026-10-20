<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Http\Uri;
use SoSecurity\Support\Guard;

/** Fixed templates and HTTPS action endpoints from private server configuration; no request-derived headers or destinations. */
final class MailTemplates
{
    private $render;
    private $configuration;
    private $actions;
    public function __construct(string $site,Address $sender,array $actionUrls,string $brand='Account security',string $language='en')
    {
        Guard::label($site);Guard::label($brand);$keys=array_keys($actionUrls);sort($keys);$expected=['cancel_change','recover_account','verify_address_new','verify_address_old','verify_registration'];
        $extended=array_merge($expected,['recover_address']);sort($extended);if(($keys!==$expected&&$keys!==$extended)||!in_array($language,['en','zh-CN'],true)||preg_match('//u',$site)!==1||preg_match('//u',$brand)!==1||strlen($brand)>128){throw new ConfigurationException('Configure five base actions, an optional mailbox recovery action and a supported language.','configuration.account_mail_templates');}
        $urls=[];$origin=null;
        foreach($actionUrls as $type=>$value){if(!is_string($value)||strlen($value)>2048){throw new ConfigurationException('Use fixed bounded HTTPS action URLs.','configuration.account_mail_templates');}$uri=Uri::parse($value);if($uri->scheme()!=='https'||$uri->target()!==$uri->path()||($origin!==null&&$uri->origin()!==$origin)){throw new ConfigurationException('Mail actions must share one explicit HTTPS origin without query or fragment.','configuration.account_mail_templates');}$origin=$uri->origin();$urls[$type]=$uri->url();}
        $this->configuration=static function()use($site):string{return $site;};$this->actions=static function()use($urls):array{return array_keys($urls);};
        $this->render=static function(DispatchNotice $delivery)use($site,$sender,$urls,$brand,$language):MailMessage{
            $notice=$delivery->notice();$type=$notice->type();$subjects=['verify_registration'=>'Verify your account','verify_address_old'=>'Approve address change','verify_address_new'=>'Confirm your new address','cancel_change'=>'Cancel address change','recover_account'=>'Recover your account','account_activated'=>'Account activated','password_changed'=>'Password changed','address_changed'=>'Address changed','recover_address'=>'Approve mailbox recovery','address_recovery_started'=>'Mailbox recovery requested','address_recovered'=>'Mailbox recovered'];
            if(strpos($type,'factor_')===0&&Notice::supports($type)){$subjects[$type]=ucfirst(str_replace('_',' ',$type));}
            if(!isset($subjects[$type])){throw new ConfigurationException('Use a fixed account notification type.','configuration.account_mail_templates');}
            $body=$brand."\n\n".($language==='zh-CN'?'安全通知：':'Security notification: ').$subjects[$type]."\n";
            if($notice->token()!==''){
                if(!isset($urls[$type])){throw new ConfigurationException('Configure the explicit recovery action URL.','configuration.account_mail_templates');}
                $fields=['selector'=>$delivery->selector(),'token'=>$notice->token()];if($type==='verify_address_old'){$fields['side']='old';}elseif($type==='verify_address_new'){$fields['side']='new';}elseif($type==='cancel_change'){$fields['side']='cancel';}
                $body.=($language==='zh-CN'?'请打开以下页面并明确确认操作。链接本身不会完成操作。':'Open this page and explicitly confirm the operation. Opening the link does not complete it.')."\n".$urls[$type].'#'.http_build_query($fields,'','&',PHP_QUERY_RFC3986)."\n\n".($language==='zh-CN'?'若非本人发起，请勿确认。':'If you did not request this operation, do not confirm it.')."\n";
            }else{$body.=($language==='zh-CN'?'这是一条已提交操作的安全通知，不包含登录或恢复凭据。':'This reports a committed account change. It contains no login or recovery credentials.')."\n";}
            $domain=substr($sender->value(),strrpos($sender->value(),'@')+1);$id='<sosecurity-'.hash('sha256',json_encode([$site,$notice->scope(),$notice->id()])).'@'.$domain.'>';
            return new MailMessage($sender,$notice->recipient(),$id,$subjects[$type],$body,$notice->issuedAt());
        };
    }
    public function validateConfiguration(string $site):void {if(!hash_equals(($this->configuration)(),$site)){throw new ConfigurationException('Mail templates belong to another site.','configuration.account_mail_templates');}}
    public function supportsAction(string $type):bool {return in_array($type,($this->actions)(),true);}
    public function render(DispatchNotice $notice):MailMessage {return ($this->render)($notice);}
    public function __debugInfo():array {return ['account_mail_templates'=>'[redacted]'];}
    public function __sleep():array {throw new ConfigurationException('Rebuild private mail templates.','configuration.account_serialization');}
    public function __wakeup():void {throw new ConfigurationException('Reload trusted mail template configuration.','configuration.account_serialization');}
    public function __set(string $name,$value):void {throw new ConfigurationException('Mail templates are immutable.','configuration.immutable');}
}
