<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;

/** Immutable content snapshot. Saver never accepts caller-built candidates as validation capabilities. */
final class Candidate
{
    private $contents;
    private $mime;
    private $extension;
    private $sourceBytes;
    private $width;
    private $height;
    public function __construct(string $contents, string $mime, string $extension, int $sourceBytes, ?int $width = null, ?int $height = null)
    {
        $this->contents = $contents; $this->mime = $mime; $this->extension = $extension; $this->sourceBytes = $sourceBytes;
        $this->width = $width; $this->height = $height;
    }
    public function contents(): string { return $this->contents; }
    public function mime(): string { return $this->mime; }
    public function extension(): string { return $this->extension; }
    public function bytes(): int { return strlen($this->contents); }
    public function sourceBytes(): int { return $this->sourceBytes; }
    public function width(): ?int { return $this->width; }
    public function height(): ?int { return $this->height; }
    public function digest(): string { return hash('sha256', $this->contents); }
    public function __set(string $name, $value): void { throw new ConfigurationException('Upload snapshots are immutable.', 'configuration.immutable'); }
}
