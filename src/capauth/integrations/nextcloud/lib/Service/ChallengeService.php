<?php

declare(strict_types=1);

namespace OCA\CapAuth\Service;

use OCP\ICache;
use OCP\IConfig;

/**
 * Issues and validates CapAuth challenge nonces.
 *
 * Nonces are stored in the Nextcloud distributed cache with a TTL.
 * Once consumed a nonce is marked as used so replay is impossible.
 */
class ChallengeService {
    private const CACHE_PREFIX  = 'capauth_nonce_';
    private const DEFAULT_TTL   = 120; // seconds

    public function __construct(
        private readonly IConfig $config,
        private readonly ICache  $cache,
    ) {}

    // ── Internal helpers ─────────────────────────────────────────────────────

    private function ttl(): int {
        return (int) $this->config->getAppValue('capauth', 'nonce_ttl', (string) self::DEFAULT_TTL);
    }

    private function cacheKey(string $nonce): string {
        return self::CACHE_PREFIX . $nonce;
    }

    private function generateUuidV4(): string {
        $data    = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Issue a new challenge for the given fingerprint.
     *
     * @return array{nonce:string, client_nonce_echo:string, issued_at:string,
     *               expires_at:string, service:string, fingerprint:string}
     */
    public function issue(string $fingerprint, string $service, string $clientNonce = ''): array {
        $fp        = strtoupper(trim($fingerprint));
        $nonce     = $this->generateUuidV4();
        $issuedAt  = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format(\DateTimeInterface::ATOM);
        $ttl       = $this->ttl();
        $expiresAt = (new \DateTimeImmutable("now +{$ttl} seconds", new \DateTimeZone('UTC')))->format(\DateTimeInterface::ATOM);
        $echo      = $clientNonce !== '' ? $clientNonce : base64_encode(random_bytes(16));

        $record = [
            'nonce'             => $nonce,
            'client_nonce_echo' => $echo,
            'issued_at'         => $issuedAt,
            'expires_at'        => $expiresAt,
            'service'           => $service,
            'fingerprint'       => $fp,
            'used'              => false,
        ];

        $this->cache->set($this->cacheKey($nonce), $record, $ttl);

        return $record;
    }

    /**
     * Consume a nonce. Returns [true, ''] on success or [false, error_code].
     *
     * @return array{0:bool, 1:string}
     */
    public function consume(string $nonce, string $fingerprint): array {
        $fp  = strtoupper(trim($fingerprint));
        $rec = $this->cache->get($this->cacheKey($nonce));

        if ($rec === null || !is_array($rec)) {
            return [false, 'invalid_nonce'];
        }
        if ($rec['used'] === true) {
            return [false, 'invalid_nonce'];
        }
        if (strtoupper($rec['fingerprint']) !== $fp) {
            return [false, 'invalid_nonce'];
        }
        if (new \DateTimeImmutable() > new \DateTimeImmutable($rec['expires_at'])) {
            return [false, 'invalid_nonce'];
        }

        // Mark consumed.
        $rec['used'] = true;
        $this->cache->set($this->cacheKey($nonce), $rec, 60);

        return [true, ''];
    }

    /**
     * Inspect a nonce without consuming it. Returns the cache record or null.
     */
    public function peek(string $nonce): ?array {
        $rec = $this->cache->get($this->cacheKey($nonce));
        return is_array($rec) ? $rec : null;
    }

    // ── Canonical payload helpers ────────────────────────────────────────────

    /**
     * Builds the deterministic plaintext that the client signs for nonce auth.
     */
    public function canonicalNoncePayload(
        string $nonce,
        string $clientNonce,
        string $issuedAt,
        string $service,
        string $expiresAt,
    ): string {
        return implode("\n", [
            'CAPAUTH_NONCE_V1',
            "nonce={$nonce}",
            "client_nonce={$clientNonce}",
            "timestamp={$issuedAt}",
            "service={$service}",
            "expires={$expiresAt}",
        ]);
    }

    /**
     * Builds the deterministic plaintext for signed identity claims.
     */
    public function canonicalClaimsPayload(
        string $fingerprint,
        string $nonce,
        array  $claims,
    ): string {
        ksort($claims);
        $claimsJson = json_encode($claims, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return implode("\n", [
            'CAPAUTH_CLAIMS_V1',
            "fingerprint={$fingerprint}",
            "nonce={$nonce}",
            "claims={$claimsJson}",
        ]);
    }
}
