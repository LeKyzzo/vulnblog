<?php

namespace App\Services;

class UserPref {

    private string $theme;

    public function __construct(
    ) {
        $cookieTheme = self::getFromCookie();
        if (!$cookieTheme) {
            $this->theme = 'light';
            self::setCookie($this->theme);
        } else {
            $this->theme = $cookieTheme;
        }
    }

    public function get(): string {
        return $this->theme;
    }

    public function switch(): void {
        $this->theme = $this->theme === 'light' ? 'dark' : 'light';
        self::setCookie($this->theme);
    }

    static public function getFromCookie(): ?string {
        $cookie = $_COOKIE['USER_PREF'] ?? null;
        if (!$cookie) {
            return null;
        }

        $data = json_decode(base64_decode(urldecode($cookie)), true);
        if (!is_array($data) || !isset($data['theme'], $data['sig'])) {
            return null;
        }

        $expected = hash_hmac('sha256', (string) $data['theme'], self::secret());
        if (!hash_equals($expected, (string) $data['sig'])) {
            return null;
        }

        return (string) $data['theme'];
    }

    static public function setCookie(string $theme): void {
        $payload = [
            'theme' => $theme,
            'sig' => hash_hmac('sha256', $theme, self::secret()),
        ];
        $data = urlencode(base64_encode(json_encode($payload)));
        setcookie('USER_PREF', $data, time() + 3600 * 24 * 365, '/', '', false, true);
    }

    private static function secret(): string
    {
        return (string) ($_ENV['APP_SECRET'] ?? '');
    }

}