<?php
declare(strict_types=1);
namespace SoSecurity\Download;
use SoSecurity\Exception\SecurityException;

/** totalBytes is provided only after authorization, never from an unverified range request. */
final class RangeException extends SecurityException
{
    private $total;
    public function __construct(?int $totalBytes=null){if($totalBytes!==null&&$totalBytes<0){throw new \SoSecurity\Exception\ConfigurationException('Invalid range size.','configuration.download_range');}parent::__construct('A single satisfiable byte range is required.','download.range');$this->total=$totalBytes;}
    public function totalBytes():?int {return $this->total;}
}
