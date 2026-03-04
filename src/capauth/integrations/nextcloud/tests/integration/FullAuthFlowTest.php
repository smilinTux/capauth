<?php

declare(strict_types=1);

namespace OCA\CapAuth\Tests\Integration;

use OCA\CapAuth\Service\ChallengeService;
use OCA\CapAuth\Service\VerifierService;
use OCP\ICache;
use OCP\IConfig;
use OCP\ILogger;
use PHPUnit\Framework\TestCase;

/**
 * Integration test: full CapAuth authentication flow.
 *
 * Uses the real ChallengeService and VerifierService against an in-memory
 * cache. Does NOT require a Nextcloud instance — all OCP dependencies are
 * mocked.
 *
 * PGP signature tests are skipped when gpg2 / gnupg extension is unavailable.
 */
class FullAuthFlowTest extends TestCase {
    private ChallengeService $challengeService;
    private VerifierService $verifierService;
    private array $cacheStore = [];

    protected function setUp(): void {
        $config = $this->createMock(IConfig::class);
        $config->method('getAppValue')->willReturnCallback(
            fn($app, $key, $default = '') => match ($key) {
                'nonce_ttl'        => '60',
                'server_key_armor' => '',
                default            => $default,
            }
        );

        $cache = $this->createMock(ICache::class);
        $cache->method('set')->willReturnCallback(function ($key, $val) {
            $this->cacheStore[$key] = $val;
            return true;
        });
        $cache->method('get')->willReturnCallback(
            fn($key) => $this->cacheStore[$key] ?? null
        );

        $logger = $this->createMock(ILogger::class);

        $this->challengeService = new ChallengeService($config, $cache);
        $this->verifierService  = new VerifierService($logger);
    }

    // ── Happy path: issue → canonical payload matches → consume ───────────

    public function testIssueThenConsumeHappyPath(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->challengeService->issue($fp, 'cloud.example.org', 'clientNonce==');

        // Canonical payload must match what the verifier rebuilds.
        $expectedPayload = $this->challengeService->canonicalNoncePayload(
            $ch['nonce'],
            $ch['client_nonce_echo'],
            $ch['issued_at'],
            $ch['service'],
            $ch['expires_at'],
        );
        $verifierPayload = $this->verifierService->canonicalNoncePayload(
            $ch['nonce'],
            $ch['client_nonce_echo'],
            $ch['issued_at'],
            $ch['service'],
            $ch['expires_at'],
        );
        $this->assertSame($expectedPayload, $verifierPayload);

        // Consume succeeds on first call.
        [$ok, $err] = $this->challengeService->consume($ch['nonce'], $fp);
        $this->assertTrue($ok, "First consume should succeed, got: {$err}");

        // Replay rejected.
        [$ok2, $err2] = $this->challengeService->consume($ch['nonce'], $fp);
        $this->assertFalse($ok2, 'Replay must be rejected');
        $this->assertSame('invalid_nonce', $err2);
    }

    public function testVerifierRejectsMissingNonceSig(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->challengeService->issue($fp, 'svc.local');

        [$ok, $err] = $this->verifierService->verifyAuthResponse(
            fingerprint:    $fp,
            nonceId:        $ch['nonce'],
            nonceSigArmor:  '',   // empty → must fail
            claims:         [],
            claimsSigArmor: '',
            publicKeyArmor: 'fake-key',
            challengeCtx:   $ch,
        );
        $this->assertFalse($ok);
        $this->assertSame('invalid_nonce_signature', $err);
    }

    public function testAnonymousAuthWithValidNonceSig(): void {
        // Mock verifySignature to return true (no real GPG needed).
        $logger = $this->createMock(ILogger::class);
        $verifier = $this->getMockBuilder(VerifierService::class)
            ->setConstructorArgs([$logger])
            ->onlyMethods(['verifySignature'])
            ->getMock();
        $verifier->method('verifySignature')->willReturn(true);

        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->challengeService->issue($fp, 'svc.local');
        // Also need to adapt challengeCtx keys to match VerifierService expectations.
        $ctx = [
            'nonce'             => $ch['nonce'],
            'client_nonce_echo' => $ch['client_nonce_echo'],
            'issued_at'         => $ch['issued_at'],
            'service'           => $ch['service'],
            'expires_at'        => $ch['expires_at'],
        ];

        [$ok, $err] = $verifier->verifyAuthResponse(
            fingerprint:    $fp,
            nonceId:        $ch['nonce'],
            nonceSigArmor:  'fake-sig',
            claims:         [],   // anonymous
            claimsSigArmor: '',
            publicKeyArmor: 'fake-key',
            challengeCtx:   $ctx,
        );
        $this->assertTrue($ok, "Anonymous auth should succeed: {$err}");
        $this->assertSame('', $err);
    }

    public function testClaimsWithoutSigRejected(): void {
        $logger = $this->createMock(ILogger::class);
        $verifier = $this->getMockBuilder(VerifierService::class)
            ->setConstructorArgs([$logger])
            ->onlyMethods(['verifySignature'])
            ->getMock();
        $callCount = 0;
        $verifier->method('verifySignature')->willReturnCallback(function() use (&$callCount) {
            return ++$callCount === 1; // nonce → true, claims → false
        });

        $fp = 'AAAA1234AAAA1234AAAA1234AAAA1234AAAA1234';
        $ch = $this->challengeService->issue($fp, 'svc.local');
        $ctx = [
            'nonce'             => $ch['nonce'],
            'client_nonce_echo' => $ch['client_nonce_echo'],
            'issued_at'         => $ch['issued_at'],
            'service'           => $ch['service'],
            'expires_at'        => $ch['expires_at'],
        ];

        [$ok, $err] = $verifier->verifyAuthResponse(
            fingerprint:    $fp,
            nonceId:        $ch['nonce'],
            nonceSigArmor:  'sig',
            claims:         ['name' => 'Alice'],   // claims present
            claimsSigArmor: '',                    // but no signature
            publicKeyArmor: 'key',
            challengeCtx:   $ctx,
        );
        $this->assertFalse($ok);
        $this->assertSame('invalid_claims_signature', $err);
    }

    // ── QR / peek flow ───────────────────────────────────────────────────────

    public function testPeekDoesNotConsume(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $ch = $this->challengeService->issue($fp, 'svc');

        // Peek three times — should never consume.
        for ($i = 0; $i < 3; $i++) {
            $rec = $this->challengeService->peek($ch['nonce']);
            $this->assertNotNull($rec);
            $this->assertFalse($rec['used']);
        }

        // Normal consume still works.
        [$ok] = $this->challengeService->consume($ch['nonce'], $fp);
        $this->assertTrue($ok);
    }
}
