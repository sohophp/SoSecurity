<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
$input = json_decode(stream_get_contents(STDIN), true);
$clock = new TestClock(); $store = new SoSecurity\Storage\MemoryStore($clock);
$policy = $input['policy'];
$limiter = new SoSecurity\RateLimit\BudgetLimiter($store, new SoSecurity\RateLimit\BudgetPolicy($policy['algorithm'], $policy['limit'], $policy['window'], $policy['burst'] ?? null, $policy['entries'] ?? 512), $clock);
$output = [];
foreach ($input['events'] as $event) {
    $clock->time = $event['at'];
    if ($event['operation'] === 'reset') { $limiter->reset('vectors', 'subject'); $output[] = null; continue; }
    $r = $limiter->{$event['operation']}('vectors', 'subject', $event['cost']);
    $output[] = [$r->allowed(), $r->remaining(), $r->retryAfter(), $r->reason()];
}
echo json_encode($output);
