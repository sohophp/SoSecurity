# Reverse proxy and WAF integration

SoSecurity does not configure the network edge or automatically trust forwarding headers. Map every hop, its source address, TLS termination, header handling, and the `REMOTE_ADDR` delivered to PHP before using an address for budgets, audit, or access rules.

1. Restrict origin and PHP access to the intended proxies at the network layer. Give any direct health-check or internal route its own identity and budget policy.
2. At the first trusted edge, remove client-supplied `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `X-Forwarded-Proto`, and vendor address headers. Write or append the actual peer according to the deployed hop chain. Verify this at every intermediary.
3. Resolve the client address in one place. If Nginx `realip` or Apache `mod_remoteip` rewrites `REMOTE_ADDR`, do not parse the same forwarding chain again in the application. For application-side `ClientIp` resolution, keep `REMOTE_ADDR` as the actual connected proxy and configure only its exact trusted CIDRs in `IpRules`.
4. `ClientIp` otherwise uses `REMOTE_ADDR`. It reads `HTTP_X_FORWARDED_FOR` only for a trusted peer and walks from the nearest hop outward. It rejects malformed addresses, more than 32 hops, or over 2048 header bytes. It does not read `Forwarded` or vendor headers.

Use the [Nginx realip](https://nginx.org/en/docs/http/ngx_http_realip_module.html) or [Apache mod_remoteip](https://httpd.apache.org/docs/2.4/en/mod/mod_remoteip.html) documentation for server-specific trust rules. Trusted proxy configuration does not verify a business identity.

The trusted deployment layer must supply the actual HTTPS state; a client-provided `X-Forwarded-Proto: https` cannot turn plain HTTP into an accepted secure request. Use a configured origin and allowed Host. Preserve distinct `Set-Cookie` headers and their security attributes, `Vary`, `Cache-Control`, and `Retry-After`; do not publicly cache authenticated or one-time responses. Enable HSTS only after the applicable HTTPS origins are verified. Set connection, request-body, upload-rate, and timeout budgets per route without replacing the component's byte and storage limits.

The trusted edge must reject duplicate authentication, signature, idempotency, and conflicting framing headers before PHP's SAPI can merge them. Merely setting the example's server-side “headers validated” property does not meet the [native idempotency contract](idempotency-native.md).

A WAF helps detect generic attack patterns and abusive traffic. Authentication, authorization, CSRF, signature verification, budgets, replay protection, Outbox transactions, and upload isolation still run in the application. Observe normal route traffic before enabling blocking, then tune false positives by precise rule, field, route, and expiry rather than disabling inspection across sensitive endpoints. The [OWASP CRS documentation](https://coreruleset.org/docs/) covers anomaly scoring and tuning. Keep WAF, proxy, and application audit logs access-controlled; never log cookies, credentials, OTPs, recovery codes, or request secrets.

Before deployment, test origin bypass, spoofed and malformed forwarding chains, forged HTTPS and Host, duplicate security headers, authenticated cookies and caches, uploads, webhooks, streaming downloads, WAF false positives, and WAF failure. Verify that application checks still run when the WAF allows a request. This repository has not validated a production proxy, WAF, certificates, or operational alerts.
