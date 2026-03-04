<?php

declare(strict_types=1);

return [
    'routes' => [
        // ── Challenge / verify flow ──────────────────────────────────────────
        [
            'name'    => 'login#challenge',
            'url'     => '/challenge',
            'verb'    => 'POST',
        ],
        [
            'name'    => 'login#nonce_status',
            'url'     => '/nonce/{nonce}/status',
            'verb'    => 'GET',
        ],
        [
            'name'    => 'login#verify',
            'url'     => '/verify',
            'verb'    => 'POST',
        ],

        // ── Token validation endpoint ────────────────────────────────────────
        // Used by external services (e.g. Nextcloud apps, CLI tools) to
        // validate a CapAuth Bearer token without going through the full
        // 2FA flow. Returns the identity claims on success.
        [
            'name'    => 'token#validate',
            'url'     => '/token/validate',
            'verb'    => 'POST',
        ],
        [
            'name'    => 'token#whoami',
            'url'     => '/token/whoami',
            'verb'    => 'GET',
        ],
    ],
];
