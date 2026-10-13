<?php
declare(strict_types=1);
namespace SoSecurity\Csrf;
use SoSecurity\Http\Uri;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\ValidationException;

/** Pure route decision. Exemption never authenticates or grants access to a route. No prefix/glob/regex bypass. */
final class RequestPolicy
{
    private $exemptions=[];
    public function __construct(array $exemptions=[])
    {
        if (count($exemptions)>32) { throw new ConfigurationException('Too many CSRF exemptions.','configuration.csrf_exemptions'); }
        foreach ($exemptions as $rule) {
            if (!is_array($rule) || count($rule)!==2 || !isset($rule['method'],$rule['path']) || !is_string($rule['method']) || !is_string($rule['path'])) {
                throw new ConfigurationException('Exemptions require exact method and path.','configuration.csrf_exemptions');
            }
            try { $this->method($rule['method']); $this->path($rule['path']); }
            catch (ValidationException $e) { throw new ConfigurationException('Invalid CSRF exemption.','configuration.csrf_exemptions',$e); }
            if (preg_match('/[^A-Za-z0-9._~\/-]/',$rule['path']) || strpos($rule['path'],'//')!==false) {
                throw new ConfigurationException('Exemptions use plain ASCII paths without encoded/ambiguous aliases.','configuration.csrf_exemptions');
            }
            $this->exemptions[$rule['method'].':'.$rule['path']]=true;
        }
    }
    public function requiresToken(string $method,string $path): bool
    {
        $this->method($method); $this->path($path);
        return !in_array($method,['GET','HEAD','OPTIONS'],true) && !isset($this->exemptions[$method.':'.$path]);
    }
    private function method(string $method): void
    {
        if (!preg_match('/\A[A-Z]{1,32}\z/D',$method)) { throw new ValidationException('Use the actual uppercase request method.','csrf.method'); }
    }
    private function path(string $path): void
    {
        if ($path==='' || $path[0]!=='/' || substr($path,0,2)==='//' || strpbrk($path,'?*#')!==false) { throw new ValidationException('Use an exact canonical route path without query/glob.','csrf.path'); }
        $uri=Uri::parse('https://csrf.invalid'.$path);
        if ($uri->path()!==$path) { throw new ValidationException('Noncanonical route path.','csrf.path'); }
    }
}
