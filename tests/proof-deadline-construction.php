<?php
declare(strict_types=1);
namespace SoSecurity\Support {
    function hrtime($numeric=false) {if($GLOBALS['proof_deadline_fault']??false){throw new \RuntimeException('owned deadline failure');}return \hrtime($numeric);}
    function microtime($numeric=false) {if($GLOBALS['proof_deadline_fault']??false){throw new \RuntimeException('owned deadline failure');}return \microtime($numeric);}
}
namespace {
    $argv=[__FILE__,'sqlite','deadline'];
    require __DIR__.'/proof-state.php';
}
