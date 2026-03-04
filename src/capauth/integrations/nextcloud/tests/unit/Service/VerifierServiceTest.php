<?php

declare(strict_types=1);

namespace OCA\CapAuth\Tests\Unit\Service;

use OCA\CapAuth\Service\VerifierService;
use OCP\ILogger;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for VerifierService.
 *
 * Signature verification tests require GnuPG or gpg2 on the test host.
 * Tests that need a real key are skipped when neither is available.
 */
class VerifierServiceTest extends TestCase {
    private VerifierService $service;
    private ILogger $logger;

    protected function setUp(): void {
        $this->logger  = $this->createMock(ILogger::class);
        $this->service = new VerifierService($this->logger);
    }

    // ── canonicalNoncePayload() ──────────────────────────────────────────────

    public function testCanonicalNoncePayloadFormat(): void {
        $out = $this->service->canonicalNoncePayload(
            'test-nonce',
            'dGVzdA==',
            '2026-02-28T12:00:00+00:00',
            'cloud.example.org',
            '2026-02-28T12:01:00+00:00',
        );
        $expected = "CAPAUTH_NONCE_V1\nnonce=test-nonce\nclient_nonce=dGVzdA==\n" .
                    "timestamp=2026-02-28T12:00:00+00:00\nservice=cloud.example.org\n" .
                    "expires=2026-02-28T12:01:00+00:00";
        $this->assertSame($expected, $out);
    }

    // ── canonicalClaimsPayload() ─────────────────────────────────────────────

    public function testCanonicalClaimsPayloadSortsKeys(): void {
        $out = $this->service->canonicalClaimsPayload(
            'FINGERPRINT123456789012345678901234567890',
            'nonce-id',
            ['sub' => 'user', 'email' => 'a@b.com', 'name' => 'Alice'],
        );
        // Sorted keys: email, name, sub
        $this->assertStringContainsString('"email":"a@b.com","name":"Alice","sub":"user"', $out);
    }

    public function testCanonicalClaimsPayloadHeaderLines(): void {
        $out = $this->service->canonicalClaimsPayload('FP', 'NONCE', []);
        $this->assertStringStartsWith("CAPAUTH_CLAIMS_V1\n", $out);
        $this->assertStringContainsString('fingerprint=FP', $out);
        $this->assertStringContainsString('nonce=NONCE', $out);
    }

    // ── verifySignature() – invalid inputs ──────────────────────────────────

    public function testVerifySignatureReturnsFalseForEmptySig(): void {
        $this->assertFalse($this->service->verifySignature('data', '', 'key'));
    }

    public function testVerifySignatureReturnsFalseForEmptyKey(): void {
        $this->assertFalse($this->service->verifySignature('data', 'sig', ''));
    }

    // ── verifyAuthResponse() – missing fields ────────────────────────────────

    public function testVerifyAuthResponseReturnsFalseOnEmptyNonceSig(): void {
        [$ok, $err] = $this->service->verifyAuthResponse(
            fingerprint:    'AAAA1234AAAA1234AAAA1234AAAA1234AAAA1234',
            nonceId:        'test-nonce',
            nonceSigArmor:  '',          // empty → must fail before key lookup
            claims:         [],
            claimsSigArmor: '',
            publicKeyArmor: 'fake-armor',
            challengeCtx:   [
                'nonce'             => 'test-nonce',
                'client_nonce_echo' => 'echo',
                'issued_at'         => '2026-02-28T00:00:00+00:00',
                'service'           => 'test',
                'expires_at'        => '2026-02-28T01:00:00+00:00',
            ],
        );
        $this->assertFalse($ok);
        $this->assertSame('invalid_nonce_signature', $err);
    }

    public function testVerifyAuthResponseRejectsClaimsWithoutSig(): void {
        // We need a valid nonce sig to get past the first check.
        // Use a mock that makes verifySignature return true for nonce.
        $service = $this->getMockBuilder(VerifierService::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['verifySignature'])
            ->getMock();

        $callCount = 0;
        $service->method('verifySignature')->willReturnCallback(function() use (&$callCount) {
            $callCount++;
            return $callCount === 1; // first call (nonce) → true, second (claims) → false
        });

        [$ok, $err] = $service->verifyAuthResponse(
            fingerprint:    'AAAA1234AAAA1234AAAA1234AAAA1234AAAA1234',
            nonceId:        'nonce',
            nonceSigArmor:  'sig',
            claims:         ['name' => 'Alice'],
            claimsSigArmor: '',  // missing sig
            publicKeyArmor: 'key',
            challengeCtx:   [
                'nonce'             => 'nonce',
                'client_nonce_echo' => '',
                'issued_at'         => '2026-02-28T00:00:00+00:00',
                'service'           => 'svc',
                'expires_at'        => '2026-02-28T01:00:00+00:00',
            ],
        );
        $this->assertFalse($ok);
        $this->assertSame('invalid_claims_signature', $err);
    }

    public function testVerifyAuthResponseSucceedsWithValidNonceSigAndNoClaims(): void {
        $service = $this->getMockBuilder(VerifierService::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['verifySignature'])
            ->getMock();
        $service->method('verifySignature')->willReturn(true);

        [$ok, $err] = $service->verifyAuthResponse(
            fingerprint:    'AAAA1234AAAA1234AAAA1234AAAA1234AAAA1234',
            nonceId:        'nonce',
            nonceSigArmor:  'sig',
            claims:         [],   // no claims – anonymous auth
            claimsSigArmor: '',
            publicKeyArmor: 'key',
            challengeCtx:   [
                'nonce'             => 'nonce',
                'client_nonce_echo' => '',
                'issued_at'         => '2026-02-28T00:00:00+00:00',
                'service'           => 'svc',
                'expires_at'        => '2026-02-28T01:00:00+00:00',
            ],
        );
        $this->assertTrue($ok);
        $this->assertSame('', $err);
    }

    // ── extractSigFromSignedMessage() via reflection ─────────────────────────

    public function testExtractSigFromSignedMessage(): void {
        $msg = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nHello\n-----BEGIN PGP SIGNATURE-----\nBase64\n-----END PGP SIGNATURE-----";
        $reflector = new \ReflectionClass(VerifierService::class);
        $method = $reflector->getMethod('extractSigFromSignedMessage');
        $method->setAccessible(true);
        $result = $method->invoke($this->service, $msg);
        $this->assertStringStartsWith('-----BEGIN PGP SIGNATURE-----', $result);
        $this->assertStringEndsWith('-----END PGP SIGNATURE-----', $result);
    }

    public function testExtractSigReturnsNullWhenNoSigBlock(): void {
        $reflector = new \ReflectionClass(VerifierService::class);
        $method = $reflector->getMethod('extractSigFromSignedMessage');
        $method->setAccessible(true);
        $this->assertNull($method->invoke($this->service, 'not a pgp message'));
    }
}
