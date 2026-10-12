<?php
declare(strict_types=1);

namespace SoSecurity\Session;

use SoSecurity\Http\Cookie;
use SoSecurity\Support\Clock;
use SoSecurity\Support\Guard;
use SoSecurity\Support\SystemClock;

final class SessionSecurity
{
    private $idle;
    private $absolute;
    private $clock;
    private $key;

    public function __construct(int $idle = 1800, int $absolute = 28800, string $namespace = 'default', ?Clock $clock = null)
    {
        $this->idle = Guard::duration($idle);
        $this->absolute = Guard::duration($absolute);
        $this->clock = $clock ?? new SystemClock();
        $this->key = '_sosecurity_session_' . Guard::label($namespace);
    }

    /** Configure BEFORE the host calls session_start(). Does not start a session itself. */
    public static function configure(bool $secure = true, string $sameSite = 'Lax'): void
    {
        if (!extension_loaded('session')) {
            throw new \RuntimeException('Native session helpers require ext-session.');
        }
        Cookie::header('PHPSESSID', '', '/', $secure, true, $sameSite);
        if (session_status() !== PHP_SESSION_NONE || headers_sent()) {
            throw new \RuntimeException('Session configuration must precede session_start and output.');
        }
        $settings = ['session.use_strict_mode' => '1', 'session.use_only_cookies' => '1',
            'session.use_cookies' => '1', 'session.use_trans_sid' => '0',
            'session.cookie_secure' => $secure ? '1' : '0', 'session.cookie_httponly' => '1',
            'session.cookie_path' => '/', 'session.cookie_domain' => '', 'session.cookie_lifetime' => '0'];
        if (PHP_VERSION_ID >= 70300) {
            $settings['session.cookie_samesite'] = $sameSite;
        }
        foreach ($settings as $name => $value) {
            if (ini_set($name, $value) === false) {
                throw new \RuntimeException('Cannot configure session setting: ' . $name);
            }
        }
    }

    /** PHP 7.2: emit this after start/rotation, replacing the native session cookie on the client. */
    public static function cookieHeader(bool $secure = true, string $sameSite = 'Lax'): string
    {
        self::active();
        return Cookie::header(session_name(), session_id(), '/', $secure, true, $sameSite);
    }

    /** False means host MUST deny authenticated actions and clear/logout its own identity. */
    public function touch(): bool
    {
        self::active();
        $now = $this->clock->now();
        $state = $_SESSION[$this->key] ?? null;
        if ($state === null) {
            $_SESSION[$this->key] = ['created' => $now, 'seen' => $now, 'expired' => false];
            return true;
        }
        if (!is_array($state) || !isset($state['created'], $state['seen'], $state['expired'])
            || !is_int($state['created']) || !is_int($state['seen']) || !is_bool($state['expired'])) {
            throw new \RuntimeException('Corrupt session timeout state.');
        }
        if ($state['expired'] || $state['created'] > $now || $state['seen'] > $now
            || $state['created'] + $this->absolute <= $now || $state['seen'] + $this->idle <= $now) {
            $_SESSION[$this->key]['expired'] = true;
            return false;
        }
        $_SESSION[$this->key]['seen'] = $now;
        return true;
    }

    /** Host calls after login/privilege change, before writing the new authenticated identity. */
    public function rotate(): void
    {
        self::active();
        if (headers_sent() || !session_regenerate_id(true)) {
            throw new \RuntimeException('Cannot rotate session ID.');
        }
        unset($_SESSION[$this->key]);
        $this->touch();
    }

    /** Mark expired only. Host remains responsible for its authentication keys and cookie deletion. */
    public function invalidate(): void
    {
        self::active();
        $now = $this->clock->now();
        $_SESSION[$this->key] = ['created' => $now, 'seen' => $now, 'expired' => true];
    }

    private static function active(): void
    {
        if (!extension_loaded('session') || session_status() !== PHP_SESSION_ACTIVE) {
            throw new \RuntimeException('The host must start the session.');
        }
    }
}
