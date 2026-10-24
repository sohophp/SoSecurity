# Vulnerability response and security release gate

This process covers the SoSecurity core package, optional adapters, examples, and distribution documentation. The private reporting channel and maintenance scope are defined in the repository [SECURITY.md](../SECURITY.md). The project does not promise a channel or response time that has not been established. The current code is an unpublished candidate; this process is not evidence of a released fix or an independent audit.

## Receive and assess

1. Record a private report identifier, receipt time, affected version or commit, PHP runtime, backend, and deployment prerequisites. Keep only the minimum reproduction data. Do not place real credentials, session IDs, OTP seeds, recovery codes, or business data in public issues, logs, or test samples.
2. Reproduce in an isolated environment and preserve the actual failing result. Database tests use only temporary local SQLite or private no-TCP MySQL instances created by the test controller. Distinguish a core defect, optional adapter defect, host configuration error, and third-party dependency advisory. An outer WAF rejection does not by itself prove an application path safe.
3. Record required attacker privileges, reachable entry points, default-configuration impact, confidentiality/integrity/availability impact, known exploit conditions, and unknown prerequisites. Mark unverified claims as pending. The maintainer determines severity and disclosure timing from evidence and may give affected users private mitigations first.
4. Check related entry points, older versions, and backends. Record the affected and unaffected range with supporting evidence. Exposed keys, tokens, or persistent state need separate rotation, revocation, and migration guidance; a patch cannot recover data already disclosed.

## Risk tiers, handling targets, and exceptions

These are internal maintainer targets for project code and actually used third-party dependencies, not an external response SLA or evidence of deployed compliance. Assign a named owner to each valid finding; missing owners, patches, or test environments do not close it. Time starts when the first locatable report or advisory becomes known; assessment does not restart the clock. Preserve uncertainties and prioritize triage when information is incomplete.

| Tier | Triage target | Mitigation target | Fix or replacement target |
| --- | --- | --- | --- |
| Emergency: exploitation evidence, or default reachability with potentially widespread account/secret compromise | 1 calendar day | 1 calendar day; disable the affected feature if necessary | 7 calendar days |
| High: confirmed serious impact with specific prerequisites and no exploitation evidence | 3 calendar days | 7 calendar days | 14 calendar days |
| Medium: limited impact or substantial privilege/complexity prerequisites | 7 calendar days | 14 calendar days | 30 calendar days |
| Low: limited hardening or low-impact issue | 14 calendar days | Decide mitigation within 30 calendar days | 90 calendar days |

Advisory scores inform assessment; record actual installation, reachability, configuration, host impact, and compensating controls. An optional dependency is not automatically unaffected. Closure records exact versions, verification, and affected consumer migration; a local patch does not establish deployment.

Each record includes first-known time, tier and rationale, named owner, deadlines, verified mitigation, exact locked dependency/commit, and patch/deployment status. Register overdue work as blocked. A maintainer-approved extension records approver, reason, residual risk, compensating controls, and a definite new expiry; it cannot erase the original overdue interval or accept risk indefinitely. Review open records every 7 calendar days and list open, overdue, and excepted items at each candidate delivery. Actual staffing, automatic reminders, and a ledger covering all consumers are not established here. Only the missing documented targets are resolved; ASVS 15.1.1/15.2.1 execution acceptance remains open.

## Fix and review record

Maintain a private record for each finding:

| Field | Required evidence |
| --- | --- |
| Scope | Report ID, exact entry point, attack prerequisites, affected commits/versions/backends, unknown conditions |
| Reproduction | Minimal local test, pre-fix failing command and actual result, private location of sensitive material |
| Fix | Code diff, fail-closed behavior, compatibility impact, data/key migration, host actions |
| Verification | Same sample after the fix, adjacent negative paths, applicable PHP versions and test backends, commands and exit codes |
| Independent review | Reviewer other than the implementer, scope, findings, disposition, residual risk; explicitly “not completed” if absent |
| Disclosure | Private notice, advisory draft, publication timing, actual release/deployment evidence; explicitly “not performed” if absent |

Use isolated test data before requesting destructive, external-service, or downstream validation from the responsible environment owner. Keep both initial failures and corrected results. Update the [threat model](threat-model.md), relevant usage guides, [changelog](../CHANGELOG.md), and tests with a security fix.

## Candidate release gate

Check these against the **same exact candidate commit**; unknown evidence remains incomplete:

1. Define the stable scope, affected versions, API/configuration compatibility, and upgrade/recovery steps. Applicable [refinement requirements](security-refinement.md) must have implementation, guidance, and matching verification. Isolated prototypes are not released features.
2. Run the full suite on PHP 7.2 through 8.5 with the claimed SQLite, private MySQL, Redis, HTTP/TLS, concurrency, and fault paths. A required check skipped for a missing extension is not a pass. Record browser and downstream acceptance separately.
3. Install fresh Composer consumers for core and optional packages, strictly validate manifests, inspect archives for source, documentation, and licenses, and exclude secrets/development artifacts. Audit each real locked third-party dependency set. A root package with no installed third-party packages has an inapplicable runtime audit, not a green advisory result.
4. Inspect actual remote CI for that commit, not merely its configuration or a historical green run. Record failures, skips, static analysis, archive checks, and reviews of security-sensitive defaults.
5. Obtain an independent review of threat boundaries, public API, secret lifecycle, hazardous state recovery, and pre-fix counterexamples. Resolve findings. Author self-review and automated scanning do not satisfy this item.
6. Prepare private user notice and public advisory with impact, fixed version, upgrade actions, residual risk, and deployment validation limits. Commit, push, tagging, package publication, registry listing, and production deployment each require the user's explicit authorization; a green gate does not trigger them.

This checklist states the evidence required for release. It does not claim that the current candidate has passed. See the [release-readiness worksheet](release-readiness.md) and [verification record](verification.md) for current status.
