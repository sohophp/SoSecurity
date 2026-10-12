<?php
declare(strict_types=1);
namespace SoSecurity\Api;
use SoSecurity\Http\Uri;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

final class SignaturePolicy
{
    private $options;
    public function __construct(array $options)
    {
        $defaults=['origin'=>null,'allow_http'=>false,'maximum_lifetime'=>300,'clock_skew'=>30,'maximum_body'=>1048576];
        if (array_diff(array_keys($options),array_keys($defaults))) { throw new ConfigurationException('Unknown signature policy option.'); }
        $options+=$defaults;
        if (!is_string($options['origin']) || !is_bool($options['allow_http'])) { throw new ConfigurationException('Configure a trusted public API origin and explicit HTTP choice.'); }
        try { $origin=Uri::originValue($options['origin']); } catch (ValidationException $e) { throw new ConfigurationException('Invalid signature origin.','configuration.api',$e); }
        if (strpos($origin,'https://')!==0 && !$options['allow_http']) { throw new ConfigurationException('API signatures require HTTPS by default.','configuration.api_https'); }
        foreach (['maximum_lifetime'=>[1,900],'clock_skew'=>[0,120],'maximum_body'=>[0,20971520]] as $name=>$range) {
            if (!is_int($options[$name]) || $options[$name]<$range[0] || $options[$name]>$range[1]) { throw new ConfigurationException('Invalid signature time/body policy.'); }
        }
        $this->options=['origin'=>$origin]; foreach ($options as $name=>$value) { if ($name!=='origin') { $this->options[$name]=$value; } }
    }
    public function options(): array { return $this->options; }
    public function maximumLifetime(): int { return $this->options['maximum_lifetime']; }
    public function clockSkew(): int { return $this->options['clock_skew']; }
    public function maximumBody(): int { return $this->options['maximum_body']; }
    public function target(string $method,string $url,string $body): string
    {
        if (!in_array($method,['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'],true) || strlen($body)>$this->maximumBody()) { throw new ValidationException('Signature method/body is invalid.','api.request'); }
        $uri=Uri::parse($url);
        if ($uri->origin()!==$this->options['origin'] || $uri->url()!==$url) { throw new ValidationException('Sign exact canonical target bytes for the configured origin.','api.target'); }
        return $url;
    }
}
