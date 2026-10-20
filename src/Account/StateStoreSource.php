<?php
declare(strict_types=1);
namespace SoSecurity\Account;
use SoSecurity\Storage\AtomicStore;
/** Explicit source coverage for a concrete protected store; construction performs no state read. */
interface StateStoreSource extends StateSnapshot
{
    public function coversStore(AtomicStore $store):bool;
}
