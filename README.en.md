# SoSecurity

Framework-independent PHP security helpers, designed for PHP 7.2 through 8.5. Package: `sohophp/sosecurity`; namespace: `SoSecurity\`. Documentation is primarily in [Simplified Chinese](README.md).

The current **0.1.0-dev local candidate** contains arithmetic/image/Turnstile CAPTCHA, stateful CSRF, atomic request budgets and bans, native password hashing and migration helpers, single-use reset tokens, opt-in session security, trusted proxy/CIDR helpers, contextual output encoding, cookies/security headers and structured audit callbacks.

No GitHub release or Packagist publication has occurred. Try it using a Composer path repository with `"require": {"sohophp/sosecurity": "@dev"}`. After publication, the intended installation command is `composer require sohophp/sosecurity`.

Storage options: locked native sessions for per-session challenges, private local filesystem for a single host, or a dedicated phpredis connection for shared atomic state. Memory storage is for tests only. Storage outages raise exceptions; the host must reject sensitive operations. Use a unique site namespace, explicit server-side binding and consistent clocks.

`bin/check.sh php` runs functional, session, HTTP and concurrency tests. Python 3 enables the HTTP integration test. Redis tools and ext-redis enable an isolated test server with no TCP listener. `python3 tests/install.py php /path/to/composer` validates installation from a fresh consumer. Static analysis tools are isolated under `tools/` and require PHP 8.1+.

PHP 7.2/7.4/8.1/8.2/8.4/8.5 are available for local checks; PHP 7.3/8.0/8.3 require CI and have not been verified locally. CI configuration is not evidence of a completed CI run. Browser, production PHP-FPM/reverse proxy, live Turnstile and independent security audit acceptance remain pending.

Uploads, SSRF, API signatures, database adapters, stateless CSRF and framework adapters are planned, not implemented. See the [roadmap](docs/roadmap.md), [usage guide](docs/usage.md), [migration guide](docs/migration.md), and [security policy](SECURITY.md).

This library does not replace authorization, parameterized SQL, HTTPS, runtime updates or infrastructure protection. Compatibility with end-of-life PHP does not restore its upstream security support. Tests do not constitute an independent security audit.

MIT License.
