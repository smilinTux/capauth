<?php

declare(strict_types=1);

namespace OCA\CapAuth\Tests\Unit\Provider;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Provider\CapAuthProvider;
use OCA\CapAuth\Service\ChallengeService;
use OCA\CapAuth\Service\VerifierService;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ISession;
use OCP\IUser;
use PHPUnit\Framework\TestCase;

class CapAuthProviderTest extends TestCase {
    private CapAuthProvider $provider;
    private ChallengeService $challengeService;
    private VerifierService $verifierService;
    private KeyRegistry $keyRegistry;
    private ISession $session;
    private IConfig $config;
    private IL10N $l10n;

    protected function setUp(): void {
        $this->challengeService = $this->createMock(ChallengeService::class);
        $this->verifierService  = $this->createMock(VerifierService::class);
        $this->keyRegistry      = $this->createMock(KeyRegistry::class);
        $this->session          = $this->createMock(ISession::class);
        $this->config           = $this->createMock(IConfig::class);
        $this->l10n             = $this->createMock(IL10N::class);
        $this->l10n->method('t')->willReturnCallback(fn($s) => $s);

        $this->provider = new CapAuthProvider(
            $this->challengeService,
            $this->verifierService,
            $this->keyRegistry,
            $this->session,
            $this->config,
            $this->l10n,
        );
    }

    // ── getId() ──────────────────────────────────────────────────────────────

    public function testGetId(): void {
        $this->assertSame('capauth', $this->provider->getId());
    }

    // ── isTwoFactorAuthEnabledForUser() ──────────────────────────────────────

    public function testIsTwoFactorEnabledWhenAutoEnrollOn(): void {
        $this->config->method('getAppValue')->willReturn('true');
        $user = $this->createMock(IUser::class);
        $this->assertTrue($this->provider->isTwoFactorAuthEnabledForUser($user));
    }

    public function testIsTwoFactorEnabledWhenAutoEnrollOffAndKeyExists(): void {
        $this->config->method('getAppValue')->willReturnCallback(
            fn($app, $key, $default) => match ($key) {
                'auto_enroll' => 'false',
                default       => $default,
            }
        );
        $user = $this->createMock(IUser::class);
        $user->method('getUID')->willReturn('alice');
        $this->keyRegistry->method('hasApprovedKey')->with('alice')->willReturn(true);
        $this->assertTrue($this->provider->isTwoFactorAuthEnabledForUser($user));
    }

    public function testIsTwoFactorDisabledWhenAutoEnrollOffAndNoKey(): void {
        $this->config->method('getAppValue')->willReturnCallback(
            fn($app, $key, $default) => match ($key) {
                'auto_enroll' => 'false',
                default       => $default,
            }
        );
        $user = $this->createMock(IUser::class);
        $user->method('getUID')->willReturn('bob');
        $this->keyRegistry->method('hasApprovedKey')->with('bob')->willReturn(false);
        $this->assertFalse($this->provider->isTwoFactorAuthEnabledForUser($user));
    }

    // ── verifyChallenge() ────────────────────────────────────────────────────

    public function testVerifyChallengeReturnsFalseForInvalidJson(): void {
        $user = $this->createMock(IUser::class);
        $this->assertFalse($this->provider->verifyChallenge($user, $this->session, 'not-json'));
    }

    public function testVerifyChallengeReturnsFalseForMissingFields(): void {
        $user = $this->createMock(IUser::class);
        $json = json_encode(['fingerprint' => 'AAAA']);  // missing nonce, nonce_signature
        $this->assertFalse($this->provider->verifyChallenge($user, $this->session, $json));
    }

    public function testVerifyChallengeReturnsFalseWhenFingerprintMismatch(): void {
        $user = $this->createMock(IUser::class);
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';

        $this->session->method('get')->willReturnCallback(fn($key) => match ($key) {
            'capauth.fingerprint' => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            default => null,
        });

        $json = json_encode([
            'fingerprint'     => $fp,
            'nonce'           => 'uuid',
            'nonce_signature' => 'sig',
        ]);
        $this->assertFalse($this->provider->verifyChallenge($user, $this->session, $json));
    }

    public function testVerifyChallengeSucceedsWhenAllChecksPass(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $challengeCtx = [
            'nonce'             => 'test-nonce',
            'client_nonce_echo' => 'echo',
            'issued_at'         => '2026-02-28T00:00:00+00:00',
            'service'           => 'svc',
            'expires_at'        => '2026-02-28T01:00:00+00:00',
        ];

        $this->session->method('get')->willReturnCallback(fn($key) => match ($key) {
            'capauth.fingerprint' => $fp,
            'capauth.challenge'   => $challengeCtx,
            default               => null,
        });

        $this->keyRegistry->method('exists')->willReturn(true);
        $this->keyRegistry->method('isApproved')->willReturn(true);
        $this->keyRegistry->method('getPublicKey')->willReturn('-----BEGIN PGP PUBLIC KEY BLOCK-----');

        $this->verifierService->method('fingerprintFromArmor')->willReturn($fp);
        $this->verifierService->method('verifyAuthResponse')->willReturn([true, '']);
        $this->keyRegistry->method('recordAuth')->willReturn(null);

        $user = $this->createMock(IUser::class);
        $json = json_encode([
            'fingerprint'     => $fp,
            'nonce'           => 'test-nonce',
            'nonce_signature' => '-----BEGIN PGP SIGNED MESSAGE-----',
        ]);
        $this->assertTrue($this->provider->verifyChallenge($user, $this->session, $json));
    }

    public function testVerifyChallengeReturnsFalseWhenKeyPendingApproval(): void {
        $fp = '1234567890ABCDEF1234567890ABCDEF12345678';
        $this->session->method('get')->willReturnCallback(fn($key) => match ($key) {
            'capauth.fingerprint' => $fp,
            'capauth.challenge'   => ['nonce' => 'n', 'client_nonce_echo' => '', 'issued_at' => '2026-02-28T00:00:00+00:00', 'service' => 's', 'expires_at' => '2026-02-28T01:00:00+00:00'],
            default => null,
        });
        $this->keyRegistry->method('exists')->willReturn(true);
        $this->keyRegistry->method('isApproved')->willReturn(false);  // pending
        $this->keyRegistry->method('getPublicKey')->willReturn('armor');
        $this->verifierService->method('fingerprintFromArmor')->willReturn($fp);

        $user = $this->createMock(IUser::class);
        $json = json_encode(['fingerprint' => $fp, 'nonce' => 'n', 'nonce_signature' => 'sig']);
        $this->assertFalse($this->provider->verifyChallenge($user, $this->session, $json));
    }
}
