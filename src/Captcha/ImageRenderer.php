<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

/** PNG renderer; third-party providers can implement their own server-side verifier separately. */
final class ImageRenderer
{
    private $width;
    private $height;
    private $font;
    private $noise;

    public function __construct(int $width = 180, int $height = 60, ?string $font = null, int $noise = 12)
    {
        if ($width < 100 || $width > 600 || $height < 40 || $height > 200 || $noise < 0 || $noise > 100) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid CAPTCHA dimensions or noise.');
        }
        if ($font !== null && (!is_file($font) || !is_readable($font))) {
            throw new \SoSecurity\Exception\ConfigurationException('Unreadable TrueType font.');
        }
        $this->width = $width;
        $this->height = $height;
        $this->font = $font;
        $this->noise = $noise;
    }

    public function render(string $answer): string
    {
        if (!preg_match('/^[A-Z0-9]{4,8}$/D', $answer) || $this->width < strlen($answer) * 18 + 16) {
            throw new \SoSecurity\Exception\ConfigurationException('Answer or width is unsuitable for CAPTCHA rendering.');
        }
        return $this->draw($answer, 22);
    }

    public function renderQuestion(string $question): string
    {
        if (!preg_match('/^[0-9]{1,2} [+*\/-] [0-9]{1,2} = \?$/D', $question)
            || $this->width < strlen($question) * 10 + 16) {
            throw new \SoSecurity\Exception\ConfigurationException('Invalid arithmetic image question or width.');
        }
        return $this->draw($question, 14);
    }

    private function draw(string $answer, int $fontSize): string
    {
        if (!extension_loaded('gd')) {
            throw new \SoSecurity\Exception\DependencyException('Image CAPTCHA requires ext-gd.');
        }
        $image = imagecreatetruecolor($this->width, $this->height);
        if ($image === false) {
            throw new \SoSecurity\Exception\DependencyException('Cannot allocate CAPTCHA image.');
        }
        $level = ob_get_level();
        try {
            $background = imagecolorallocate($image, 245, 245, 245);
            $foreground = imagecolorallocate($image, 25, 45, 70);
            $noise = imagecolorallocate($image, 150, 165, 180);
            imagefill($image, 0, 0, $background);
            for ($i = 0; $i < $this->noise; ++$i) {
                imageline($image, random_int(0, $this->width - 1), random_int(0, $this->height - 1),
                    random_int(0, $this->width - 1), random_int(0, $this->height - 1), $noise);
            }
            $step = ($this->width - 16) / strlen($answer);
            for ($i = 0; $i < strlen($answer); ++$i) {
                $x = (int) (8 + $i * $step);
                if ($this->font === null) {
                    imagechar($image, 5, $x, (int) ($this->height / 2 - 8), $answer[$i], $foreground);
                } elseif (imagettftext($image, $fontSize, random_int(-15, 15), $x,
                    (int) ($this->height / 2 + 10), $foreground, $this->font, $answer[$i]) === false) {
                    throw new \SoSecurity\Exception\DependencyException('Cannot render CAPTCHA font.');
                }
            }
            ob_start();
            if (!imagepng($image)) {
                throw new \SoSecurity\Exception\DependencyException('Cannot encode CAPTCHA image.');
            }
            return (string) ob_get_clean();
        } finally {
            while (ob_get_level() > $level) {
                ob_end_clean();
            }
            // GdImage objects are released automatically on PHP 8; avoid deprecated imagedestroy there.
            if (PHP_VERSION_ID < 80000) {
                imagedestroy($image);
            }
        }
    }
}
