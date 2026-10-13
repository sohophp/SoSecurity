<?php
declare(strict_types=1);

namespace SoSecurity\Captcha;

/** @internal Private solutions must never be serialized into a public response. */
final class InteractiveRenderer
{
    private static function canvas(int $width, int $height)
    {
        if (!extension_loaded('gd')) { throw new \SoSecurity\Exception\DependencyException('Interactive CAPTCHA requires ext-gd.'); }
        $image = imagecreatetruecolor($width, $height);
        if ($image === false) { throw new \SoSecurity\Exception\DependencyException('Cannot allocate CAPTCHA image.'); }
        imagefill($image, 0, 0, imagecolorallocate($image, 235, 242, 250));
        return $image;
    }

    private static function release($image): void
    {
        if (PHP_VERSION_ID < 80000) { imagedestroy($image); }
    }

    private static function png($image): string
    {
        $level = ob_get_level();
        try {
            ob_start();
            if (!imagepng($image)) { throw new \SoSecurity\Exception\DependencyException('Cannot encode CAPTCHA image.'); }
            return (string) ob_get_clean();
        } finally { while (ob_get_level() > $level) { ob_end_clean(); } }
    }

    public static function slider(): array
    {
        $image = self::canvas(300, 150);
        $piece = null;
        try {
            // Procedural texture avoids external images, URLs and upload dependencies.
            for ($i = 0; $i < 45; ++$i) {
                $color = imagecolorallocate($image, random_int(50, 200), random_int(75, 210), random_int(100, 230));
                imagefilledellipse($image, random_int(0, 299), random_int(0, 149), random_int(15, 100), random_int(15, 70), $color);
            }
            $x = random_int(65, 250); $y = random_int(12, 98); $size = 40;
            $piece = self::canvas($size, $size);
            imagecopy($piece, $image, 0, 0, $x, $y, $size, $size);
            imagerectangle($piece, 0, 0, 39, 39, imagecolorallocate($piece, 255, 255, 255));
            imagefilledrectangle($image, $x, $y, $x + 39, $y + 39, imagecolorallocate($image, 35, 48, 65));
            imagerectangle($image, $x, $y, $x + 39, $y + 39, imagecolorallocate($image, 255, 255, 255));
            return ['answer' => $x, 'image' => self::png($image), 'presentation' => [
                'kind' => 'slider', 'width' => 300, 'height' => 150, 'piece_width' => 40,
                'piece_y' => $y, 'piece' => self::png($piece)]];
        } finally {
            self::release($image);
            if ($piece !== null) { self::release($piece); }
        }
    }

    public static function click(): array
    {
        $image = self::canvas(300, 180);
        try {
            $pool = str_split('ABCDEFGHJKLMNPQRSTUVWXYZ');
            for ($i = count($pool) - 1; $i > 0; --$i) {
                $j = random_int(0, $i); $swap = $pool[$i]; $pool[$i] = $pool[$j]; $pool[$j] = $swap;
            }
            $foreground = imagecolorallocate($image, 25, 45, 70);
            $noise = imagecolorallocate($image, 185, 200, 215);
            for ($i = 0; $i < 9; ++$i) {
                $x = ($i % 3) * 100; $y = intdiv($i, 3) * 60;
                for ($n = 0; $n < 4; ++$n) {
                    imageline($image, $x + random_int(0, 99), $y + random_int(0, 59),
                        $x + random_int(0, 99), $y + random_int(0, 59), $noise);
                }
                imagerectangle($image, $x, $y, $x + 99, $y + 59, $noise);
                // Built-in GD font, enlarged using nearest-neighbour resampling; no font file needed.
                $glyph = self::canvas(9, 16);
                try {
                    imagechar($glyph, 5, 0, 0, $pool[$i], imagecolorallocate($glyph, 25, 45, 70));
                    imagecopyresized($image, $glyph, $x + 38 + random_int(-4, 4), $y + 8, 0, 0, 27, 48, 9, 16);
                } finally { self::release($glyph); }
            }
            $indices = range(0, 8);
            for ($i = 8; $i > 0; --$i) {
                $j = random_int(0, $i); $swap = $indices[$i]; $indices[$i] = $indices[$j]; $indices[$j] = $swap;
            }
            $selected = array_slice($indices, 0, 3);
            return ['answer' => implode(',', $selected), 'image' => self::png($image),
                'prompt' => '依次点击：' . implode(' → ', array_map(function (int $i) use ($pool): string { return $pool[$i]; }, $selected)),
                'presentation' => ['kind' => 'click', 'width' => 300, 'height' => 180, 'rows' => 3, 'columns' => 3, 'count' => 3]];
        } finally { self::release($image); }
    }
}
