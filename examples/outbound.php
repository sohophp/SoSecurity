<?php
declare(strict_types=1);
namespace SoSecurity\Examples;

use SoSecurity\Http\Outbound\Client;
use SoSecurity\Http\Outbound\Response;

/** Host provides an already configured exact-host client and owns endpoint authorization/response semantics. */
function requestStatus(Client $client, string $approvedUrl): Response
{
    return $client->request('GET', $approvedUrl, ['Accept'=>'application/json']);
}
