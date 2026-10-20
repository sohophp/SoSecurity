#!/usr/bin/env python3
"""Independent rational-token and accepted-event oracle; no PHP state-layout assumptions."""
from fractions import Fraction
from math import ceil
from pathlib import Path
import json, random, subprocess, sys
runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
root = Path(__file__).resolve().parent.parent
checks = 0
for algorithm in ['token_bucket', 'fixed_window', 'sliding_window']:
    for limit, window, burst, entries in [(7, 13, 11, 3), (1, 1, 2, 1), (97, 101, 23, 32)]:
        capacity = burst if algorithm == 'token_bucket' else limit
        policy = dict(algorithm=algorithm, limit=limit, window=window)
        if algorithm == 'token_bucket': policy['burst'] = burst
        if algorithm == 'sliding_window': policy['entries'] = entries
        rng = random.Random(4827); now = 100000; events = []; expected = []; state = None
        for i in range(1200):
            now += rng.choice([0, 0, 1, 2, window-1, window, window+1])
            operation = 'reset' if i % 127 == 126 else ('inspect' if rng.randrange(4) == 0 else 'consume')
            cost = rng.choice([1, 2, 3, capacity, capacity+1]); events.append(dict(at=now, operation=operation, cost=cost))
            if operation == 'reset': state = None; expected.append(None); continue
            if cost > capacity: expected.append([False, 0, 0, 'rate.cost_exceeds_limit']); continue
            retry = 0; reason = 'rate.allowed'
            if algorithm == 'token_bucket':
                balance = Fraction(capacity) if state is None else min(Fraction(capacity), state[1]+Fraction((now-state[0])*limit, window))
                allowed = balance >= cost
                if not allowed: retry = ceil((cost-balance)*window/limit)
                if operation == 'consume':
                    if allowed: balance -= cost
                    state = (now, balance)
                remaining = int(balance)
            elif algorithm == 'fixed_window':
                start, used = (now, 0) if state is None or state[0]+window <= now else state
                allowed = used+cost <= limit
                if not allowed: retry = start+window-now
                if operation == 'consume':
                    if allowed: used += cost
                    state = (start, used)
                remaining = limit-used
            else:
                history = [] if state is None else [(at, cost) for at, cost in state if at+window > now]
                used = sum(cost for _, cost in history); same = bool(history and history[-1][0] == now)
                capacity_full = not same and len(history) >= entries; allowed = not capacity_full and used+cost <= limit
                if not allowed:
                    releases = sorted(set(at+window for at, _ in history))
                    retry = next(exp-now for exp in releases if sum(weight for at, weight in history if at+window > exp)+cost <= limit and (not capacity_full or history[0][0]+window <= exp))
                    reason = 'rate.capacity' if capacity_full else 'rate.exhausted'
                if operation == 'consume':
                    if allowed:
                        if same: history[-1] = (now, history[-1][1]+cost)
                        else: history.append((now, cost))
                        used += cost
                    state = history
                remaining = limit-used
            expected.append([allowed, remaining, retry, reason if allowed or algorithm == 'sliding_window' else 'rate.exhausted'])
        result = subprocess.run([runtime, str(root/'tests/budget-vectors.php')], input=json.dumps(dict(policy=policy, events=events)), capture_output=True, text=True, check=True)
        actual = json.loads(result.stdout)
        for index, (want, got) in enumerate(zip(expected, actual)):
            assert want == got, (policy, index, events[index], want, got)
        assert len(actual) == len(expected); checks += len(expected)
print(f'PASS independent budget vectors: {checks} rational-token / fixed / exact-second accepted-history cases')
