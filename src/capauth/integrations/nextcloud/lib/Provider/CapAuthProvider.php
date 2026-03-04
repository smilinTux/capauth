<?php

declare(strict_types=1);

namespace OCA\CapAuth\Provider;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Service\ChallengeService;
use OCA\CapAuth\Service\VerifierService;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\IConfig;
use OCP\IL10N;
use OCP\ISession;
use OCP\IUser;
use OCP\Template;

/**
 * Nextcloud two-factor auth provider backed by CapAuth PGP challenge-response.
 *
 * Flow:
 *   1. beginAuthentication() stores a fresh nonce in the session and renders
 *      the challenge template (QR or polling link).
 *   2. verifyChallenge() receives the signed JSON payload from the client,
 *      checks the fingerprint against the approved key registry, then
 *      delegates to VerifierService for actual PGP verification.
 */
class CapAuthProvider implements IProvider {
    public function __construct(
        private readonly ChallengeService $challengeService,
        private readonly VerifierService  $verifierService,
        private readonly KeyRegistry      $keyRegistry,
        private readonly ISession         $session,
        private readonly IConfig          $config,
        private readonly IL10N            $l10n,
    ) {}

    // ── IProvider interface ──────────────────────────────────────────────────

    public function getId(): string {
        return 'capauth';
    }

    public function getDisplayName(): string {
        return $this->l10n->t('CapAuth PGP Key');
    }

    public function getDescription(): string {
        return $this->l10n->t('Sign in with your CapAuth PGP key');
    }

    public function isTwoFactorAuthEnabledForUser(IUser $user): bool {
        $autoEnroll = $this->config->getAppValue('capauth', 'auto_enroll', 'false');
        if ($autoEnroll === 'true') {
            return true;
        }
        return $this->keyRegistry->hasApprovedKey($user->getUID());
    }

    public function beginAuthentication(IUser $user, ISession $session): Template {
        $service  = $this->config->getAppValue('capauth', 'service_name', \OC::$server->getRequest()->getServerHost());
        $fp       = $session->get('capauth.fingerprint') ?? '';
        $challenge = $this->challengeService->issue($fp, $service);
        $session->set('capauth.challenge', $challenge);

        $tmpl = new Template('capauth', 'challenge');
        $tmpl->assign('challenge', $challenge);
        return $tmpl;
    }

    /**
     * Verify a CapAuth challenge response.
     *
     * The $challenge string is a JSON object from the browser:
     * {
     *   "fingerprint":     "AABB...",
     *   "nonce":           "<uuid>",
     *   "nonce_signature": "-----BEGIN PGP SIGNED MESSAGE-----...",
     *   "claims":          { ... },          // optional
     *   "claims_signature": "..."            // required when claims present
     * }
     */
    public function verifyChallenge(IUser $user, ISession $session, string $challenge): bool {
        $payload = json_decode($challenge, true);
        if (!is_array($payload)) {
            return false;
        }

        $fp          = $payload['fingerprint']     ?? '';
        $nonceId     = $payload['nonce']            ?? '';
        $nonceSig    = $payload['nonce_signature']  ?? '';
        $claims      = $payload['claims']           ?? [];
        $claimsSig   = $payload['claims_signature'] ?? '';

        if ($fp === '' || $nonceId === '' || $nonceSig === '') {
            return false;
        }

        // Verify the fingerprint matches what was stored at challenge issue time.
        $storedFp = $session->get('capauth.fingerprint');
        if ($storedFp !== null && strtoupper($storedFp) !== strtoupper($fp)) {
            return false;
        }

        // Fetch the challenge context stored in the session.
        $challengeCtx = $session->get('capauth.challenge');
        if (!is_array($challengeCtx)) {
            return false;
        }

        // Look up the registered key.
        if (!$this->keyRegistry->exists($fp)) {
            return false;
        }

        $publicKeyArmor = $this->keyRegistry->getPublicKey($fp);
        if ($publicKeyArmor === null) {
            return false;
        }

        // Validate armor fingerprint matches claimed fingerprint.
        $armorFp = $this->verifierService->fingerprintFromArmor($publicKeyArmor);
        if ($armorFp !== '' && strtoupper($armorFp) !== strtoupper($fp)) {
            return false;
        }

        // Key must be approved.
        if (!$this->keyRegistry->isApproved($fp)) {
            return false;
        }

        [$ok, $err] = $this->verifierService->verifyAuthResponse(
            fingerprint:    $fp,
            nonceId:        $nonceId,
            nonceSigArmor:  $nonceSig,
            claims:         is_array($claims) ? $claims : [],
            claimsSigArmor: $claimsSig,
            publicKeyArmor: $publicKeyArmor,
            challengeCtx:   $challengeCtx,
        );

        if ($ok) {
            $this->keyRegistry->recordAuth($fp);
        }

        return $ok;
    }
}
