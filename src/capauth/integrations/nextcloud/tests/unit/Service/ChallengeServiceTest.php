<?php

declare(strict_types=1);

namespace OCA\CapAuth\Tests\Unit\Service;

use OCA\CapAuth\Service\ChallengeService;
use OCP\ICache;
use OCP\IConfig;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for ChallengeService.
 *
 * We mock IConfig and ICache so no Nextcloud infrastructure is required.
 */
class ChallengeServiceTest extends TestCase {
    private ChallengeService $service;
    /** @var IConfig&MockObject */
    private IConfig $config;
    /** @var ICache&MockObject */
    private ICache $cache;

    /** In-memory cache backing store for tests. */
    private array $cacheStore = [];

    protected function setUp(): void {
        $this->config = $this->createMock(IConfig::class);
        $this->cache  = $this->createMock(ICache::class);

        // Config stubs.
        $this->config->method('getAppValue')->willReturnCallback(
            fn($app, $key, $default = '') => match ($key) {
                'nonce_ttl'            => '60',
                'server_key_armor'     => '',
                default                => $default,
            }
        );

        // Cache stubs – back by $this->cacheStore.
        $this->cache->method('set')->willReturnCallback(function ($key, $val) {
            $this->cacheStore[$key] = $val;
            return true;
        });
        $this->cache->method('get')->willReturnCallback(
            fn($key) => $this->cacheStore[$key] ?? null
        );

        $this->service = new ChallengeService($this->config, $this->cache);
    }

    // ── issue() ─────────────────────────────────────────────────────────────

    public function testIssueReturnsChallengeWithRequiredFields(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->service->issue($fp, 'cloud.example.org');

        $this->assertArrayHasKey('nonce', $ch);
        $this->assertArrayHasKey('client_nonce_echo', $ch);
        $this->assertArrayHasKey('issued_at', $ch);
        $this->assertArrayHasKey('expires_at', $ch);
        $this->assertArrayHasKey('service', $ch);
        $this->assertSame('cloud.example.org', $ch['service']);
        $this->assertSame($fp, $ch['fingerprint']);
    }

    public function testIssueNonceIsUuidV4(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->service->issue($fp, 'test.local');
        $nonce = $ch['nonce'];
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i',
            $nonce
        );
    }

    public function testIssueNormalisesFingerprint(): void {
        $fp = strtolower('1234567890abcdef1234567890abcdef12345678');
        $ch = $this->service->issue($fp, 'test.local');
        $this->assertSame(strtoupper($fp), $ch['fingerprint']);
    }

    public function testIssueEchoesClientNonce(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->service->issue($fp, 'test.local', 'abc123==');
        $this->assertSame('abc123==', $ch['client_nonce_echo']);
    }

    public function testIssueGeneratesClientNonceWhenNotProvided(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->service->issue($fp, 'test.local', '');
        $this->assertNotEmpty($ch['client_nonce_echo']);
    }

    // ── consume() ───────────────────────────────────────────────────────────

    public function testConsumeSucceedsOnFirstUse(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->service->issue($fp, 'test.local');
        [$ok, $err] = $this->service->consume($ch['nonce'], $fp);
        $this->assertTrue($ok);
        $this->assertSame('', $err);
    }

    public function testConsumeRejectsSecondUse(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->service->issue($fp, 'test.local');
        $this->service->consume($ch['nonce'], $fp);
        [$ok, $err] = $this->service->consume($ch['nonce'], $fp);
        $this->assertFalse($ok);
        $this->assertSame('invalid_nonce', $err);
    }

    public function testConsumeRejectsUnknownNonce(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        [$ok, $err] = $this->service->consume('00000000-0000-0000-0000-000000000000', $fp);
        $this->assertFalse($ok);
        $this->assertSame('invalid_nonce', $err);
    }

    public function testConsumeRejectsMismatchedFingerprint(): void {
        $fp  = '1234567890ABCDEF1234567890ABCDEF12345678';
        $fp2 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        $ch = $this->service->issue($fp, 'test.local');
        [$ok, $err] = $this->service->consume($ch['nonce'], $fp2);
        $this->assertFalse($ok);
        $this->assertSame('invalid_nonce', $err);
    }

    // ── peek() ──────────────────────────────────────────────────────────────

    public function testPeekReturnsRecordWithoutConsuming(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->service->issue($fp, 'test.local');
        $rec = $this->service->peek($ch['nonce']);
        $this->assertNotNull($rec);
        $this->assertFalse($rec['used']);
    }

    public function testPeekReturnsNullForUnknownNonce(): void {
        $this->assertNull($this->service->peek('nonexistent-uuid'));
    }

    // ── canonicalNoncePayload() ──────────────────────────────────────────────

    public function testCanonicalNoncePayloadMatchesPythonFormat(): void {
        $payload = $this->service->canonicalNoncePayload(
            'abc-nonce',
            'base64==',
            '2026-02-28T12:00:00+00:00',
            'cloud.example.org',
            '2026-02-28T12:01:00+00:00',
        );

        $expected = implode("\n", [
            'CAPAUTH_NONCE_V1',
            'nonce=abc-nonce',
            'client_nonce=base64==',
            'timestamp=2026-02-28T12:00:00+00:00',
            'service=cloud.example.org',
            'expires=2026-02-28T12:01:00+00:00',
        ]);
        $this->assertSame($expected, $payload);
    }

    // ── canonicalClaimsPayload() ─────────────────────────────────────────────

    public function testCanonicalClaimsPayloadSortsKeys(): void {
        $claims = ['email' => 'a@b.c', 'name' => 'Alice'];
        $payload = $this->service->canonicalClaimsPayload(
            'AAAA1234AAAA1234AAAA1234AAAA1234AAAA1234',
            'abc-nonce',
            $claims,
        );
        // email must come before name (alphabetical).
        $this->assertStringContainsString('"email":"a@b.c","name":"Alice"', $payload);
    }
}
