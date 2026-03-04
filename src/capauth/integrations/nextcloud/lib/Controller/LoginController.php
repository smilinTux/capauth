<?php

declare(strict_types=1);

namespace OCA\CapAuth\Controller;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Service\ChallengeService;
use OCA\CapAuth\Service\VerifierService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;

/**
 * HTTP endpoints for the CapAuth challenge/response login flow.
 *
 * Routes (defined in appinfo/routes.php):
 *   POST /capauth/challenge              → challenge()
 *   GET  /capauth/nonce/{nonce}/status   → nonceStatus()
 *   POST /capauth/verify                 → verify()
 */
class LoginController extends Controller {
    public function __construct(
        string                          $appName,
        IRequest                        $request,
        private readonly ChallengeService $challengeService,
        private readonly VerifierService  $verifierService,
        private readonly KeyRegistry      $keyRegistry,
        private readonly ISession         $session,
        private readonly IUserSession     $userSession,
        private readonly IUserManager     $userManager,
        private readonly IConfig          $config,
    ) {
        parent::__construct($appName, $request);
    }

    // ── Challenge issuance ───────────────────────────────────────────────────

    /**
     * POST /capauth/challenge
     * Body: { "fingerprint": "...", "client_nonce": "..." }
     *
     * Returns the challenge context the client must sign.
     *
     * @NoCSRFRequired
     * @PublicPage
     */
    public function challenge(): JSONResponse {
        $body        = $this->parseJsonBody();
        $fingerprint = trim($body['fingerprint'] ?? '');
        $clientNonce = $body['client_nonce'] ?? '';

        if (!$this->isValidFingerprint($fingerprint)) {
            return new JSONResponse(
                ['error' => 'invalid_fingerprint'],
                Http::STATUS_BAD_REQUEST,
            );
        }

        $service   = $this->config->getAppValue(
            'capauth',
            'service_name',
            $this->request->getServerHost(),
        );
        $challenge = $this->challengeService->issue($fingerprint, $service, $clientNonce);

        // Store fingerprint and challenge in server-side session for 2FA flow.
        $this->session->set('capauth.fingerprint', strtoupper($fingerprint));
        $this->session->set('capauth.challenge', $challenge);

        return new JSONResponse($challenge);
    }

    // ── Nonce status polling ─────────────────────────────────────────────────

    /**
     * GET /capauth/nonce/{nonce}/status
     *
     * Returns: { "status": "pending"|"consumed"|"expired"|"unknown" }
     *
     * @NoCSRFRequired
     * @PublicPage
     */
    public function nonceStatus(string $nonce): JSONResponse {
        $rec = $this->challengeService->peek($nonce);
        if ($rec === null) {
            return new JSONResponse(['status' => 'unknown']);
        }
        if ($rec['used']) {
            return new JSONResponse(['status' => 'consumed']);
        }
        if (new \DateTimeImmutable() > new \DateTimeImmutable($rec['expires_at'])) {
            return new JSONResponse(['status' => 'expired']);
        }
        return new JSONResponse(['status' => 'pending']);
    }

    // ── Verification + session establishment ─────────────────────────────────

    /**
     * POST /capauth/verify
     * Body: {
     *   "fingerprint":      "...",
     *   "nonce":            "...",
     *   "nonce_signature":  "...",
     *   "claims":           { ... },    // optional
     *   "claims_signature": "..."       // required when claims present
     * }
     *
     * @NoCSRFRequired
     * @PublicPage
     */
    public function verify(): JSONResponse {
        $body        = $this->parseJsonBody();
        $fingerprint = strtoupper(trim($body['fingerprint'] ?? ''));
        $nonceId     = $body['nonce']            ?? '';
        $nonceSig    = $body['nonce_signature']  ?? '';
        $claims      = $body['claims']           ?? [];
        $claimsSig   = $body['claims_signature'] ?? '';

        if (!$this->isValidFingerprint($fingerprint) || $nonceId === '' || $nonceSig === '') {
            return new JSONResponse(['error' => 'bad_request'], Http::STATUS_BAD_REQUEST);
        }

        // Consume nonce (prevents replay).
        [$nonceOk, $nonceErr] = $this->challengeService->consume($nonceId, $fingerprint);
        if (!$nonceOk) {
            return new JSONResponse(['error' => $nonceErr], Http::STATUS_UNAUTHORIZED);
        }

        // Retrieve the challenge context stored when the nonce was issued.
        $challengeCtx = $this->session->get('capauth.challenge');
        if (!is_array($challengeCtx)) {
            return new JSONResponse(['error' => 'no_challenge'], Http::STATUS_UNAUTHORIZED);
        }

        // Retrieve and validate the public key.
        if (!$this->keyRegistry->isApproved($fingerprint)) {
            return new JSONResponse(['error' => 'key_not_approved'], Http::STATUS_FORBIDDEN);
        }
        $publicKeyArmor = $this->keyRegistry->getPublicKey($fingerprint);
        if ($publicKeyArmor === null) {
            return new JSONResponse(['error' => 'key_not_found'], Http::STATUS_NOT_FOUND);
        }

        [$ok, $err] = $this->verifierService->verifyAuthResponse(
            fingerprint:    $fingerprint,
            nonceId:        $nonceId,
            nonceSigArmor:  $nonceSig,
            claims:         is_array($claims) ? $claims : [],
            claimsSigArmor: $claimsSig,
            publicKeyArmor: $publicKeyArmor,
            challengeCtx:   $challengeCtx,
        );

        if (!$ok) {
            return new JSONResponse(['error' => $err], Http::STATUS_UNAUTHORIZED);
        }

        // Find Nextcloud user linked to this fingerprint.
        $uid  = $this->keyRegistry->getUid($fingerprint);
        $user = $uid !== null ? $this->userManager->get($uid) : null;

        if ($user === null) {
            return new JSONResponse(['error' => 'user_not_found'], Http::STATUS_NOT_FOUND);
        }

        $this->keyRegistry->recordAuth($fingerprint);
        $this->userSession->setUser($user);

        return new JSONResponse(['status' => 'ok', 'uid' => $uid]);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private function parseJsonBody(): array {
        $raw = file_get_contents('php://input');
        if ($raw === false || $raw === '') {
            return [];
        }
        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    private function isValidFingerprint(string $fp): bool {
        return (bool) preg_match('/^[0-9A-Fa-f]{40}$/', $fp);
    }
}
