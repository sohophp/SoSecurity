<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;

final class StoredFile
{
    private $path;
    private $metadata;
    public function __construct(string $path, Candidate $candidate, bool $scanned)
    {
        $this->path = static function () use ($path): string { return $path; };
        $this->metadata = ['filename' => basename($path), 'bytes' => $candidate->bytes(), 'source_bytes' => $candidate->sourceBytes(),
            'mime' => $candidate->mime(), 'sha256' => $candidate->digest(), 'width' => $candidate->width(), 'height' => $candidate->height(),
            'scanner_passed' => $scanned];
    }
    /** Server-side integration only; never serialize this path into a public response. */
    public function path(): string { return ($this->path)(); }
    public function metadata(): array { return $this->metadata; }
    public function __debugInfo(): array { return ['upload_file' => $this->metadata]; }
    public function __sleep(): array { throw new ConfigurationException('Persist explicit upload metadata without private paths.', 'configuration.upload_serialization'); }
    public function __wakeup(): void { throw new ConfigurationException('Reload trusted upload records.', 'configuration.upload_serialization'); }
}
