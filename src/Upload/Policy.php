<?php
declare(strict_types=1);
namespace SoSecurity\Upload;

use SoSecurity\Exception\ConfigurationException;

final class Policy
{
    private const TYPES = ['jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png', 'webp' => 'image/webp',
        'pdf' => 'application/pdf', 'txt' => 'text/plain'];
    private $options;
    public function __construct(array $options = [])
    {
        $defaults = ['extensions' => ['jpg', 'jpeg', 'png'], 'maximum_bytes' => 5242880, 'maximum_width' => 4096,
            'maximum_height' => 4096, 'maximum_pixels' => 4000000, 'working_bytes' => 134217728, 'jpeg_quality' => 85, 'require_scan' => false];
        if (array_diff(array_keys($options), array_keys($defaults))) { throw new ConfigurationException('Unknown upload policy option.'); }
        $options += $defaults;
        if (!is_array($options['extensions']) || !$options['extensions'] || count($options['extensions']) > 6) { throw new ConfigurationException('Choose a bounded extension allowlist.'); }
        $extensions = [];
        foreach ($options['extensions'] as $extension) {
            if (!is_string($extension) || !isset(self::TYPES[$extension]) || in_array($extension, $extensions, true)) {
                throw new ConfigurationException('Upload extensions must be distinct supported lowercase names.');
            }
            $extensions[] = $extension;
        }
        $limits = ['maximum_bytes' => [1, 20971520], 'maximum_width' => [1, 16384], 'maximum_height' => [1, 16384],
            'maximum_pixels' => [1, 16000000], 'working_bytes' => [1048576, 536870912], 'jpeg_quality' => [1, 95]];
        foreach ($limits as $name => $range) {
            if (!is_int($options[$name]) || $options[$name] < $range[0] || $options[$name] > $range[1]) { throw new ConfigurationException('Invalid upload resource limit.'); }
        }
        if (!is_bool($options['require_scan'])) { throw new ConfigurationException('Upload scan requirement must be boolean.'); }
        $this->options = ['extensions' => $extensions];
        foreach ($options as $name => $value) { if ($name !== 'extensions') { $this->options[$name] = $value; } }
    }
    public function options(): array { return $this->options; }
    public function maximumBytes(): int { return $this->options['maximum_bytes']; }
    public function maximumWidth(): int { return $this->options['maximum_width']; }
    public function maximumHeight(): int { return $this->options['maximum_height']; }
    public function maximumPixels(): int { return $this->options['maximum_pixels']; }
    public function workingBytes(): int { return $this->options['working_bytes']; }
    public function jpegQuality(): int { return $this->options['jpeg_quality']; }
    public function requiresScan(): bool { return $this->options['require_scan']; }
    public function mime(string $extension): ?string { return in_array($extension, $this->options['extensions'], true) ? self::TYPES[$extension] : null; }
    public function __set(string $name, $value): void { throw new ConfigurationException('Upload policy is immutable.', 'configuration.immutable'); }
}
