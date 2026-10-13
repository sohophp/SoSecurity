# SoSecurity

Framework-independent, modular PHP Web security helpers for **PHP 7.2–8.5**. Composer package: `sohophp/sosecurity`; namespace: `SoSecurity\`. Start with the [Chinese documentation index](docs/index.md).

The current version is an **unreleased development candidate**. Use a local Composer path repository with `"sohophp/sosecurity": "@dev"`; the intended command after public release is `composer require sohophp/sosecurity`. The core requires PHP, JSON and hash, with no mandatory third-party runtime package.

Capabilities include CAPTCHA, stateful and signed stateless CSRF, application rate limiting and automatic/manual bans, passwords/reset tokens, opt-in session helpers, contextual output encoding, strict input validation, optional reviewed HTML cleanup, private uploads, HTTP/CORS/proxy/redirect policies, bounded pinned outbound HTTP, API credentials/HMAC/nonces, audit callbacks and diagnostics. Automatic bans reuse RateLimit; there is no system Fail2ban integration or separate AutoBan package.

Components work independently. The optional `Security::fromArray()` factory validates configuration without starting sessions, sending headers, connecting services or creating directories. Seven [configuration presets](examples/configuration-presets.php) demonstrate the common choices. Connections and private keys are explicitly supplied by the host. Shared sensitive state requires a suitable atomic backend; MemoryStore is test-only.

The [interactive local demo](http://72.rocky.wsl/SoSecurity/) covers normal, rejected and fault paths. Unconfigured external services are labelled accurately. Standalone [examples](examples) show gradual migration without replacing host authentication, routing, persistence or session ownership. Existing projects are only changed when explicitly requested.

All nine target PHP versions have local functional, fresh Composer consumer, isolated Redis/MySQL/HTTP and concurrency evidence. See [verification](docs/verification.md), [feature coverage](docs/features.md), [configuration](docs/configuration.md), [migration](docs/migration.md), [architecture](docs/architecture.md) and [contributing](CONTRIBUTING.md). CI configuration and author tests are not an independent audit or production acceptance.

Current work is limited to SoSecurity, standalone examples and the designated demo in the current environment. Previous Windows results are historical coverage; no further Windows setup is part of this plan. Private filesystem support and other boundaries remain explicit in [platform coverage](docs/platforms.md).

The library does not replace authorization, parameterized SQL, HTTPS, runtime updates or infrastructure protection. Compatibility with end-of-life PHP does not restore upstream support. [Security reporting](SECURITY.md) · MIT License.
