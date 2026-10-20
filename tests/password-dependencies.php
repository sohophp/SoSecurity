<?php
declare(strict_types=1);
namespace SoSecurity\Http\Outbound {
    function extension_loaded(string $name): bool { return false; } // Isolated missing native transport capability.
}
namespace {
    require __DIR__ . '/bootstrap.php';
    Check::throws(SoSecurity\Exception\DependencyException::class, function () { (new SoSecurity\Password\PwnedPasswords())('Public test phrase 39!'); });
    Check::same(false, (new SoSecurity\Password\PwnedPasswords(function () { return str_repeat('0', 35) . ':0'; }))('Public test phrase 39!'));
    echo "PASS password transport capability: missing native transport refused; explicit range adapter remains available\n";
}
