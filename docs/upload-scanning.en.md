# Upload scanning

`Upload\ClamAvScanner` implements the existing `Scanner` interface using an explicitly configured local Unix socket. Construction does not contact the service. Saver scans its immutable validated snapshot before writing the same bytes into private storage outside the web root.

Use the [standalone builder](../examples/clamav-scanner.php), or inject the adapter as the existing `upload.scanner` service with `require_scan=true`. Authentication, object authorization, CSRF, quotas and request budgets belong before saving. Register availability only after Saver returns successfully.

The [official ClamD protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) uses NUL-framed INSTREAM commands and length-prefixed binary chunks. This adapter sends bounded 8192-byte chunks, never a client filename or server-side path. One real elapsed-time deadline covers connecting, writing, reading and final checks. The budget is 1–30000ms; the default input limit is 5MiB and the maximum configurable limit is 20MiB.

Replies are capped at 4096 bytes and read until EOF. Only one exact clean response succeeds. Malware results return false; limits, errors, malformed or extra replies, stalled writes and timeouts fail closed. Saver maps rejection to `upload.scan_rejected` and dependency failures to `upload.scan_failed`, without creating a destination file.

Socket paths must be canonical absolute local paths of at most 100 bytes. Socket and parent identity/permissions are checked before and after the exchange; symlinks, writable parent directories, world-writable sockets and replacements are rejected. Administrators must protect all ancestors and the configured service. Filesystem checks are not cryptographic peer authentication.

Daemon options cannot be changed over this protocol. Follow the [service documentation](https://docs.clamav.net/manual/Usage/Scanning.html): keep engine/signatures maintained, align stream/file limits with the client, bound expanded scan resources, enable `AlertExceedsMax`, and define an encrypted-content policy. A clean response does not establish universal safety or replace validation, CDR, authorization or controlled downloads.

This adapter provides synchronous scanning. The separately constructed [Quarantine workflow](upload-quarantine.en.md) adds persistent pending jobs, bounded asynchronous retries, administrative actions and rescanning; full R4.4 acceptance remains open. `scanner_passed` describes the trusted save flow, not a download capability or a client-provided assertion. Diagnostics remain manual and do not send sample data automatically.

Protocol tests create owned local socket peers. The separate real-service test launches and cleans up a private no-TCP clamd with synthetic data and a test-only signature database. That verifies integration, not official malware coverage or production readiness. See the [verification record](verification.md) for current results and remaining R4.4 work.
