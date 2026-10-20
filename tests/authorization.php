<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
use SoSecurity\Auth\Account;
use SoSecurity\Auth\CallbackIdentityProvider;
use SoSecurity\Authorization\Authorizer;
use SoSecurity\Authorization\CallbackPolicy;
use SoSecurity\Authorization\Decision;
use SoSecurity\Authorization\PolicySet;
use SoSecurity\Authorization\Resource;
use SoSecurity\Authorization\RolePolicy;
use SoSecurity\Exception\ConfigurationException;
use SoSecurity\Exception\DependencyException;
use SoSecurity\Exception\SecurityException;
use SoSecurity\Exception\ValidationException;

$actor = new Account('tenant', 'alice', '1', true, ['editor']); $current = $actor; $offline = false; $reads = 0;
$source = new CallbackIdentityProvider(function () { return null; }, function () use (&$current, &$offline, &$reads) {
    ++$reads; if ($offline) { throw new RuntimeException('PRIVATE-IDENTITY-FAILURE'); } return $current;
});
$owner = 'alice'; $attributes = ['owner' => &$owner, 'state' => 'draft']; $resource = new Resource('tenant', 'document', 'a', '1', $attributes); $owner = 'other';
Check::same('alice', $resource->attributes()['owner']);
$copy = $resource->attributes(); $copy['owner'] = 'other'; Check::same('alice', $resource->attributes()['owner']);
Check::same((new Resource('tenant', 'document', 'a', '1', ['state' => 'draft', 'owner' => 'alice']))->fingerprint(), $resource->fingerprint());
$rule = ['type' => 'document', 'roles' => ['editor'], 'fields' => ['title', 'body'], 'owner_attribute' => 'owner', 'match' => ['state' => 'draft']];
$policy = new RolePolicy(['document.update' => $rule]);
$authorizer = new Authorizer($source, $policy);
Check::same(false, (new Authorizer($source))->decide('tenant', $actor, 'document.update', $resource)->allowed());
Check::same(false, $authorizer->decide('tenant', null, 'document.update', $resource)->allowed());
Check::same(false, $authorizer->decide('tenant', $actor, 'unknown', $resource)->allowed());
$reads = 0;
Check::same(true, $authorizer->decide('tenant', $actor, 'document.update', $resource, ['title'])->allowed());
Check::same(['title', 'body'], $authorizer->decide('tenant', $actor, 'document.update', $resource)->fields());
Check::same(4, $reads);
Check::same(false, $authorizer->decide('tenant', $actor, 'document.update', $resource, ['owner'])->allowed());
Check::throws(SecurityException::class, function () use ($authorizer, $actor, $resource) { $authorizer->assertAllowed('tenant', $actor, 'document.update', $resource, ['owner']); });
foreach ([new Resource('other', 'document', 'a', '1', ['owner' => 'alice', 'state' => 'draft']),
    new Resource('tenant', 'document', 'b', '1', ['owner' => 'bob', 'state' => 'draft']),
    new Resource('tenant', 'document', 'c', '1', ['owner' => 'alice', 'state' => 'published']),
    new Resource('tenant', 'document', 'd', '1', ['state' => 'draft'])] as $denied) {
    Check::same(false, $authorizer->decide('tenant', $actor, 'document.update', $denied, ['title'])->allowed());
    Check::same(false, $authorizer->decideBatch('tenant', $actor, 'document.update', [$resource, $denied], ['title'])->allowed());
}
foreach ([new Account('tenant', 'alice', '1', true, ['admin']), new Account('tenant', 'alice', '2', true, ['editor']), new Account('tenant', 'alice', '1', false, ['editor']), null] as $changed) {
    $current = $changed; Check::same(false, $authorizer->decide('tenant', $actor, 'document.update', $resource)->allowed());
}
$current = $actor; $offline = true;
try { $authorizer->decide('tenant', $actor, 'document.update', $resource); throw new LogicException('Expected source failure.'); }
catch (DependencyException $e) { Check::same('authorization.unavailable', $e->reason()); Check::same(null, $e->getPrevious()); Check::same(false, strpos($e->getMessage(), 'PRIVATE') !== false); }
$offline = false;
$changing = new Authorizer($source, new CallbackPolicy(function () use (&$current) { $current = new Account('tenant', 'alice', '2', true, ['editor']); return Decision::allow(['title']); }));
Check::same(false, $changing->decide('tenant', $actor, 'document.update', $resource, ['title'])->allowed()); $current = $actor;
foreach ([function () { return true; }, function () { throw new RuntimeException('PRIVATE-POLICY-FAILURE'); }] as $bad) {
    Check::throws(DependencyException::class, function () use ($source, $actor, $resource, $bad) { (new Authorizer($source, new CallbackPolicy($bad)))->assertAllowed('tenant', $actor, 'document.update', $resource); });
}
$allow = new CallbackPolicy(function () { return Decision::allow(['title']); });
$all = new Authorizer($source, new PolicySet([$policy, $allow]));
Check::same(true, $all->decide('tenant', $actor, 'document.update', $resource, ['title'])->allowed());
Check::same(false, $all->decide('tenant', $actor, 'document.update', $resource, ['body'])->allowed());
Check::same(false, (new Authorizer($source, new PolicySet([])))->decide('tenant', $actor, 'document.update', $resource)->allowed());
foreach ([null, Decision::deny()] as $answer) {
    Check::same(false, (new Authorizer($source, new PolicySet([$allow, new CallbackPolicy(function () use ($answer) { return $answer; })])))->decide('tenant', $actor, 'document.update', $resource)->allowed());
}
Check::same(['title' => 'Allowed'], $all->project('tenant', $actor, 'document.update', $resource, ['title' => 'Allowed', 'secret' => 'PRIVATE'], ['title']));
Check::throws(ConfigurationException::class, function () use ($all, $actor, $resource) { $all->project('tenant', $actor, 'document.update', $resource, [], ['title']); });
Check::throws(SecurityException::class, function () use ($all, $actor, $resource) { $all->project('tenant', $actor, 'document.update', $resource, ['secret' => 'PRIVATE'], ['secret']); });
foreach ([[], [$resource, $resource], array_fill(0, 101, $resource), ['a' => $resource], [new stdClass()]] as $bad) {
    Check::throws(ValidationException::class, function () use ($all, $actor, $bad) { $all->decideBatch('tenant', $actor, 'document.update', $bad); });
}
foreach ([['*'], ['title', 'title'], ['nested.name'], ['0'], [1], ['x' => 'title']] as $bad) {
    Check::throws(ValidationException::class, function () use ($all, $actor, $resource, $bad) { $all->decide('tenant', $actor, 'document.update', $resource, $bad); });
}
$hundred = [];
for ($i = 0; $i < 100; ++$i) { $hundred[] = new Resource('tenant', 'document', (string) $i, '1', ['owner' => 'alice', 'state' => 'draft']); }
Check::same(true, $all->decideBatch('tenant', $actor, 'document.update', $hundred, ['title'])->allowed());
foreach ([['private' => new stdClass()], ['private' => []], ['private' => str_repeat('x', 1025)], ['private' => "\xff"], array_fill_keys(range('a', 'i'), str_repeat('x', 1024))] as $bad) {
    Check::throws(ConfigurationException::class, function () use ($bad) { new Resource('tenant', 'document', 'a', '1', $bad); });
}
foreach ([['document.*' => $rule], ['document.update' => array_merge($rule, ['unknown' => true])], ['document.update' => array_merge($rule, ['roles' => []])], ['document.update' => array_merge($rule, ['owner_attribute' => null])]] as $bad) {
    Check::throws(ConfigurationException::class, function () use ($bad) { new RolePolicy($bad); });
}
$events = []; $audit = new SoSecurity\Audit\AuditLogger(function ($event) use (&$events) { $events[] = $event; }, str_repeat('a', 32));
$logged = new Authorizer($source, $policy, $audit); $logged->assertAllowed('tenant', $actor, 'document.update', $resource, ['title']);
Check::same(1, count($events)); Check::same(['allowed' => true], $events[0]['context']); Check::same(false, strpos(json_encode($events), 'alice') !== false);
$failingAudit = new SoSecurity\Audit\AuditLogger(function () { throw new RuntimeException('PRIVATE-AUDIT-FAILURE'); }, str_repeat('a', 32));
Check::throws(DependencyException::class, function () use ($source, $policy, $failingAudit, $actor, $resource) { (new Authorizer($source, $policy, $failingAudit))->assertAllowed('tenant', $actor, 'document.update', $resource); });
foreach ([$resource, Decision::allow(), $authorizer, $policy, $allow, new PolicySet([$policy])] as $value) { Check::throws(ConfigurationException::class, function () use ($value) { serialize($value); }); }
$factory = SoSecurity\Security::fromArray(['site' => 'p', 'authorization' => ['identity_provider' => 'identity', 'policy' => 'policy']], ['identity' => $source, 'policy' => $policy]);
Check::same(true, $factory->authorization()->decide('tenant', $actor, 'document.update', $resource, ['title'])->allowed());
Check::same(false, SoSecurity\Security::fromArray(['site' => 'p', 'authorization' => ['identity_provider' => 'identity']], ['identity' => $source])->authorization()->decide('tenant', $actor, 'document.update', $resource)->allowed());
Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site' => 'p', 'authorization' => []]); });
Check::throws(ConfigurationException::class, function () { SoSecurity\Security::fromArray(['site' => 'p'])->authorization(); });
foreach (['identity_provider', 'policy', 'audit'] as $missing) {
    Check::throws(ConfigurationException::class, function () use ($missing, $source, $policy) { SoSecurity\Security::fromArray(['site' => 'p', 'authorization' => ['identity_provider' => 'identity', $missing => 'missing']], ['identity' => $source, 'policy' => $policy])->authorization(); });
}
Check::same(PHP_SESSION_NONE, session_status()); Check::same(false, headers_sent());
echo 'PASS authorization: ' . Check::$assertions . ' assertions on PHP ' . PHP_VERSION . "; default deny, current identity, role/owner/attribute constraints, field masks, all-of batches and audit failures\n";
