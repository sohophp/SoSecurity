# SoSecurity

Framework-independent PHP security helpers, designed for PHP 7.2 through 8.5. Package: `sohophp/sosecurity`; namespace: `SoSecurity\`. Documentation is primarily in [Simplified Chinese](README.md).

The current **unreleased local candidate (HTTP/API stage)** contains arithmetic/image/Turnstile CAPTCHA, stateful CSRF, atomic request budgets and bans, native password hashing and migration helpers, single-use reset tokens, opt-in session security, trusted proxy/CIDR helpers, contextual output encoding, cookies/security headers and structured audit callbacks.

No GitHub release or Packagist publication has occurred. Try it using a Composer path repository with `"require": {"sohophp/sosecurity": "@dev"}`. After publication, the intended installation command is `composer require sohophp/sosecurity`.

A local interactive demo is available at [72.rocky.wsl/SoSecurity](http://72.rocky.wsl/SoSecurity/). It covers the implemented capabilities and diagnostics with server-rendered forms, AJAX and actual rejection paths. Unconfigured external services are labelled pending. Only `demo/public` is exposed; the library repository is denied HTTP access. Demo assets are excluded from the Composer package. See [demo deployment](docs/demo.md).

Storage options: locked native sessions for per-session challenges, private local filesystem for a single host, a dedicated phpredis connection with explicit initialization, or a dedicated PDO MySQL/InnoDB table for shared atomic state. Memory storage is for tests only. Storage outages raise exceptions; the host must reject sensitive operations. Use a unique site namespace, explicit server-side binding and consistent clocks.

`bin/check.sh php` runs functional, session, HTTP and concurrency tests. Python 3 enables the HTTP integration test. Redis tools and ext-redis enable an isolated test server with no TCP listener. `python3 tests/install.py php /path/to/composer` validates installation from a fresh consumer. Static analysis tools are isolated under `tools/` and require PHP 8.1+.

PHP 7.2/7.4/8.1/8.2/8.4/8.5 are available for local checks; PHP 7.3/8.0/8.3 require CI and have not been verified locally. CI configuration is not evidence of a completed CI run. The local demo Chromium and PHP-FPM paths have been verified; production-site browser/reverse-proxy, live Turnstile and independent security audit acceptance remain pending.

API credentials and the bounded RFC 9421 HMAC/atomic nonce profile are implemented; see [API guide](docs/api.md). Signed stateless CSRF with authenticated-login binding, double-submit verification and exact route policies is implemented; see [signed CSRF guide](docs/signed-csrf.md). Optional framework adapters remain planned. See the [roadmap](docs/roadmap.md), [usage guide](docs/usage.md), [migration guide](docs/migration.md), and [security policy](SECURITY.md).

This library does not replace authorization, parameterized SQL, HTTPS, runtime updates or infrastructure protection. Compatibility with end-of-life PHP does not restore its upstream security support. Tests do not constitute an independent security audit.

MIT License.

The unreleased candidate now includes strict bounded input validation and dedicated PDO MySQL/InnoDB atomic storage. These remain framework independent. Redis requires explicit trusted initialization and reviewed restart recovery. See [MySQL](docs/mysql.md), [validation](docs/validation.md), and [Redis recovery](docs/redis-recovery.md) for current APIs and boundaries. API credentials/signatures now have interactive demonstrations and independent Python interoperability checks.

[Upload validation and private storage](docs/upload.md) now support bounded content inspection, image decode/reencoding, exclusive random names and scanner/file-manager adapters. The demo upload area is private and quota/retention limited; no public file serving route is added.

Exact-origin redirects/CORS, opt-in Permissions-Policy and bounded pinned outbound HTTP are now implemented. See [HTTP policies](docs/http-policy.md) and [outbound requests](docs/outbound.md), including DNS provider privacy, redirect/credential behavior and transport evidence.
