<?php
declare(strict_types=1);

/** Include after the host Composer autoloader. Only an actual save contacts the configured local daemon. */
return static function(string $socketPath,string $privateDirectory,string $documentRoot):SoSecurity\Upload\Saver{
    $maximum=5242880;
    $scanner=new SoSecurity\Upload\ClamAvScanner($socketPath,5000,$maximum);
    return new SoSecurity\Upload\Saver(new SoSecurity\Upload\Validator(new SoSecurity\Upload\Policy([
        'extensions'=>['jpg','jpeg','png'],'maximum_bytes'=>$maximum,'require_scan'=>true,
    ])),$privateDirectory,$documentRoot,$scanner);
};
