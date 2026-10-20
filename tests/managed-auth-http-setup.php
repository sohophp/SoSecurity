<?php
declare(strict_types=1);
// CLI only: creates an owned local SQLite account, migrated factor and fence.
require __DIR__.'/account-factor/revocation-support.php';
$environment=new ManagedEnvironment();
$environment->clock->time=time();
revocationSetup($environment);
echo json_encode(['directory'=>$environment->directory,'secret'=>$environment->secret,'password'=>$environment->password,'recovery'=>$environment->codes[0]]);
