<?php
declare(strict_types=1);
namespace SoSecurity\Examples;

use SoSecurity\Captcha\Captcha;
use SoSecurity\Captcha\Challenge;
use SoSecurity\Exception\ConfigurationException;

/** Independent, framework-free selection helper. Do not take scope/binding from untrusted input. */
function createCaptchaChallenge(Captcha $captcha, string $kind,
    string $scope, string $binding): Challenge
{
    switch ($kind) {
        case 'digits': return $captcha->imageDigits($scope, $binding);
        case 'letters': return $captcha->imageLetters($scope, $binding);
        case 'image': return $captcha->image($scope, $binding);
        case 'image_math': return $captcha->imageArithmetic($scope, $binding);
        case 'slider': return $captcha->slider($scope, $binding);
        case 'click': return $captcha->click($scope, $binding);
        case 'add': case 'subtract': case 'multiply': case 'divide': case 'mixed':
            return $captcha->arithmetic($scope, $binding, $kind);
        default: throw new ConfigurationException('Unknown CAPTCHA form.');
    }
}
