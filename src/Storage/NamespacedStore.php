<?php
declare(strict_types=1);
namespace SoSecurity\Storage;
use SoSecurity\Support\Guard;

final class NamespacedStore implements AtomicStore
{
    private $store;
    private $namespace;
    public function __construct(AtomicStore $store, string $namespace)
    {
        Guard::label($namespace); $this->store = $store; $this->namespace = $namespace;
    }
    public function transact(string $key, callable $callback)
    {
        Guard::label($key);
        return $this->store->transact('scope:' . hash('sha256', $this->namespace . "\0" . $key), $callback);
    }
    public function underlying(): AtomicStore { return $this->store; }
}
