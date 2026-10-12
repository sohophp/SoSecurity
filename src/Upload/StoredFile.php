<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

final class StoredFile
{
    private $path;
    private $metadata;
    public function __construct(string $path, Candidate $candidate, bool $scanned)
    {
        $this->path = $path;
        $this->metadata = ['filename' => basename($path), 'bytes' => $candidate->bytes(), 'source_bytes' => $candidate->sourceBytes(),
            'mime' => $candidate->mime(), 'sha256' => $candidate->digest(), 'width' => $candidate->width(), 'height' => $candidate->height(),
            'scanner_passed' => $scanned];
    }
    /** Server-side integration only; never serialize this path into a public response. */
    public function path(): string { return $this->path; }
    public function metadata(): array { return $this->metadata; }
}
