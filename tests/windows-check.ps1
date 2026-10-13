param([string]$Php = 'php')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    # This is the explicitly bounded Windows suite. Shared drivers, private file saving and network are separate gates.
    $checks = @('tests/windows-platform.php', 'bin/api-contract.php', 'tests/portable-core.php',
        'tests/signed-csrf.php', 'tests/validation.php', 'tests/http-policy.php', 'tests/outbound.php',
        'tests/session.php', 'tests/html.php', 'tests/html-dependencies.php', 'tests/reset-flow.php')
    foreach ($check in $checks) {
        & $Php $check
        if ($LASTEXITCODE -ne 0) { throw "Windows check failed: $check" }
    }
    & $Php tests/html-dependencies.php old
    if ($LASTEXITCODE -ne 0) { throw 'Windows old HTML dependency rejection failed.' }
    Write-Output 'PASS bounded native Windows suite; no Linux/full-driver/platform-parity claim'
} finally {
    Pop-Location
}
