<?php
declare(strict_types=1);
namespace SoSecurity\Examples;
use SoSecurity\Csrf\SignedTokens;

/** Host authenticates the current login before calling either helper; Cookie/header emission remains explicit. */
function signedFormToken(SignedTokens $csrf,string $scope,string $verifiedLoginBinding,$cookie): string
{
    return $csrf->reuseOrIssue($scope,$verifiedLoginBinding,$cookie);
}
function verifySignedForm(SignedTokens $csrf,string $scope,string $verifiedLoginBinding,$cookie,$formToken,$headerToken): bool
{
    if ($formToken!==null && $headerToken!==null && (!is_string($formToken) || !is_string($headerToken) || !hash_equals($formToken,$headerToken))) { return false; }
    return $csrf->verifyDoubleSubmit($scope,$verifiedLoginBinding,$cookie,$formToken ?? $headerToken);
}
