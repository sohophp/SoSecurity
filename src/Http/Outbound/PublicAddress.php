<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound;

use SoSecurity\Http\IpRules;

/** Conservative IANA-special-address exclusion, not a claim about a deployment's routing topology. */
final class PublicAddress
{
    public static function allows(string $ip): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) { return false; }
        if (strlen($packed) === 4) {
            return !(new IpRules(['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
                '172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16',
                '198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4']))->contains($ip);
        }
        return (new IpRules(['2000::/3']))->contains($ip)
            && !(new IpRules(['2001::/23','2001:db8::/32','2002::/16','3ffe::/16','3fff::/20']))->contains($ip);
    }
}
