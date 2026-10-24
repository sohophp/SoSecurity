# Optional read-only ZIP inspection

The inspection budget starts before the first file I/O and covers hashing, directory preflight, opening the archive, content reads, and final source verification. It uses a monotonic clock when available; PHP 7.2 falls back to wall time and rejects backward movement. Expiry or clock failure remains `upload.archive` without a nested clock exception. Checkpoints cannot interrupt a running system call; the host must still enforce a process timeout.

`SoSecurity\Upload\ArchiveInspector` checks a host-staged local ZIP file without extracting entries or calling application code. The host still owns upload authorization, private staging, malware scanning, process-level timeouts, and the decision to use an inspected file. The ordinary upload and quarantine flows do not invoke this optional inspector automatically.

```php
$result = (new \SoSecurity\Upload\ArchiveInspector())->inspect($privateZipPath);
// sha256, entries (path/directory/bytes), and uncompressed_bytes
```

The source itself must be a regular local file with one hard link, not a symbolic link; the host must supply a private parent directory that attackers cannot replace. The inspector verifies the source device, inode, length, and SHA-256 again before returning. A successful result describes that read only; it does not authorize extraction or later reuse of the path. The default limits are 16 MiB archive bytes, 100 entries, 1024 path bytes, eight path segments, 4 MiB per expanded file, 32 MiB total expanded bytes, a 100:1 expansion ratio, and a 10-second inspection deadline. Constructor limits may only reduce these values. Missing `ext-zip` raises `dependency.archive`; invalid policy raises `configuration.archive`; unsafe, corrupt, or oversized archives raise `upload.archive`. See the [standalone example](../examples/archive-inspection.php).

Before opening the archive with libzip, the inspector bounds and parses its end and central directories, local header names, entry count, and metadata lengths. It rejects multi-disk archives, ZIP64, inconsistent names or offsets, duplicate paths, path traversal, absolute or Windows paths, hidden segments, device names, trailing dots, symlinks and special entries, file/directory conflicts, and nested archive names or content signatures. It streams every regular entry, checking its actual byte count and CRC. No output directory or extraction callback is accepted. Any later extraction feature would require a separate security design and implementation.

Local tests use generated private files. Six installed `ext-zip` runtimes across PHP 7.2–8.5 passed 47 focused assertions each under an 8 MiB PHP memory limit; three runtimes without the extension passed explicit dependency-refusal checks. PHP 7.2 and 8.5 package archives and fresh Composer consumers passed. Downstream-host and production acceptance remain separate. Compatibility references: [PHP `getStream`](https://www.php.net/manual/en/ziparchive.getstream.php), [`getStreamIndex`](https://www.php.net/manual/en/ziparchive.getstreamindex.php), and the [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
