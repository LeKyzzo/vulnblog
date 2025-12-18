<?php

namespace App\Services;

use Psr\Log\LoggerInterface;

class Analytics
{
    public function __construct(
        private readonly bool $trackingEnabled,
        private readonly LoggerInterface $logger
    )
    {
    }

    public function track(): void {
        if (!$this->trackingEnabled) {
            return;
        }

        // Get the referer header
        $referer = $_SERVER['HTTP_REFERER'] ?? null;
        if (!$referer || !$this->validate($referer)) {
            return;
        }

        // Log sanitized referer without executing shell commands
        $this->logger->info('Referer captured', ['referer' => $referer]);
    }

    public function validate(string $url): bool
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return false;
        }

        $parts = parse_url($url);
        if (!isset($parts['scheme'], $parts['host']) || !in_array($parts['scheme'], ['http', 'https'], true)) {
            return false;
        }

        $host = $parts['host'];
        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return false;
        }

        $ip = gethostbyname($host);
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }
}