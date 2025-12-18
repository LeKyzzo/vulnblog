<?php

namespace App\Services;

use Psr\Log\LoggerInterface;

class Avatar
{

    public function __construct(
        private readonly LoggerInterface $logger
    ) {
    }

    public function getFromUrl(string $url): string|false
    {
        try {
            $context = stream_context_create([
                'http' => [
                    'timeout' => 5,
                    'follow_location' => false,
                ],
                'https' => [
                    'timeout' => 5,
                    'follow_location' => false,
                ],
            ]);
            $content = file_get_contents($url, false, $context);
        } catch (\Exception $e) {
            $this->logger->error('Error getting avatar from URL: ' . $e->getMessage());
            return false;
        }

        return $content;
    }
}