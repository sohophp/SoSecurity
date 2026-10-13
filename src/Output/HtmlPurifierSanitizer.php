<?php
declare(strict_types=1);
namespace SoSecurity\Output;
use SoSecurity\Exception\DependencyException;

/** Fixed basic-text policy only; arbitrary provider settings/hooks/resources/trusted HTML are not exposed. */
final class HtmlPurifierSanitizer implements HtmlSanitizer
{
    private $purifier;
    public function __construct(bool $allowLinks=true)
    {
        if (!class_exists('HTMLPurifier') || !defined('HTMLPurifier::VERSION')) { throw new DependencyException('Install optional ezyang/htmlpurifier.','dependency.htmlpurifier'); }
        if (!self::supportsVersion(\HTMLPurifier::VERSION)) { throw new DependencyException('Use reviewed HTML Purifier 4.19.1+ within 4.x.','dependency.htmlpurifier_version'); }
        if (!extension_loaded('ctype')) { throw new DependencyException('HTML Purifier requires ext-ctype.','dependency.ctype'); }
        if (!extension_loaded('dom')) { throw new DependencyException('The reviewed DOM lexer requires ext-dom.','dependency.dom'); }
        $config=\HTMLPurifier_Config::createDefault();
        $allowed='p,br,div,span,strong,b,em,i,u,s,del,blockquote,ul,ol,li,h2,h3,h4,pre,code';
        if ($allowLinks) { $allowed.=',a[href|title]'; }
        $config->set('Core.Encoding','UTF-8');
        $config->set('HTML.Allowed',$allowed);
        $config->set('HTML.Trusted',false);
        $config->set('HTML.SafeIframe',false);
        $config->set('URI.AllowedSchemes',['http'=>true,'https'=>true,'mailto'=>true]);
        $config->set('URI.DisableResources',true);
        $config->set('URI.DisableExternalResources',true);
        $config->set('Cache.DefinitionImpl',null);
        $config->set('Core.AllowParseManyTags',false);
        $this->purifier=new \HTMLPurifier($config);
    }
    public function sanitize(string $html): string { return $this->purifier->purify($html); }
    public static function supportsVersion(string $version): bool
    {
        return preg_match('/\A4\.[0-9]+\.[0-9]+\z/D',$version)===1 && version_compare($version,'4.19.1','>=');
    }
}
