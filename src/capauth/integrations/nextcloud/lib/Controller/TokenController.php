<?php

declare(strict_types=1);

namespace OCA\CapAuth\Controller;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Service\VerifierService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;

/**
 * Token validation endpoints.
 *
 * POST /capauth/token/validate
 *   Validates a CapAuth Bearer token submitted in the request body.
 *   Returns the decoded claims on success so callers can inspect identity.
 *   Body: { "token": "<base64url-or-raw-json>" }
 *
 * GET /capauth/token/whoami
 *   Returns the identity of the currently authenticated CapAuth session
 *   (fingerprint + claims) if a valid Bearer token was processed by the
 *   PgpVerificationMiddleware in this request.
 */
class TokenController extends Controller {
    public function __construct(
        string                      $appName,
        IRequest                    $request,
        private readonly ISession          $session,
        private readonly KeyRegistry       $keyRegistry,
        private readonly VerifierService   $verifierService,
        private readonly IConfig           $config,
    ) {
        parent::__construct($appName, $request);
    }

    // ── POST /capauth/token/validate ─────────────────────────────────────────

    /**
     * @NoCSRFRequired
     * @PublicPage
     */
    public function validate(): JSONResponse {
        $body  = $this->parseJsonBody();
        $token = $body['token'] ?? '';

        if ($token === '') {
            return new JSONResponse(['error' => 'missing_token'], Http::STATUS_BAD_REQUEST);
        }

        $envelope = $this->decodeToken($token);
        if ($envelope === null) {
            return new JSONResponse(['error' => 'malformed_token'], Http::STATUS_BAD_REQUEST);
        }

        $fingerprint = strtoupper(trim($envelope['fingerprint'] ?? ''));
        $nonce       = $envelope['nonce']       ?? '';
        $issuedAt    = $envelope['issued_at']   ?? '';
        $service     = $envelope['service']     ?? '';
        $signature   = $envelope['signature']   ?? '';
        $claims      = $envelope['claims']      ?? [];
        $claimsSig   = $envelope['claims_signature'] ?? '';

        if (!preg_match('/^[0-9A-F]{40}$/', $fingerprint) || $nonce === '' || $signature === '') {
            return new JSONResponse(['error' => 'invalid_token_fields'], Http::STATUS_BAD_REQUEST);
        }

        // Verify token age.
        if (!$this->tokenWithinWindow($issuedAt)) {
            return new JSONResponse(['error' => 'token_expired'], Http::STATUS_UNAUTHORIZED);
        }

        // Look up the key.
        if (!$this->keyRegistry->isApproved($fingerprint)) {
            return new JSONResponse(['error' => 'key_not_approved'], Http::STATUS_FORBIDDEN);
        }
        $publicKeyArmor = $this->keyRegistry->getPublicKey($fingerprint);
        if ($publicKeyArmor === null) {
            return new JSONResponse(['error' => 'key_not_found'], Http::STATUS_NOT_FOUND);
        }

        // Build challenge context from the token itself.
        $ttl          = (int) $this->config->getAppValue('capauth', 'nonce_ttl', '120');
        $expiresAt    = (new \DateTimeImmutable($issuedAt))->modify("+{$ttl} seconds")->format(\DateTimeInterface::ATOM);
        $challengeCtx = [
            'nonce'             => $nonce,
            'client_nonce_echo' => $envelope['client_nonce_echo'] ?? '',
            'issued_at'         => $issuedAt,
            'service'           => $service,
            'expires_at'        => $expiresAt,
        ];

        [$ok, $err] = $this->verifierService->verifyAuthResponse(
            fingerprint:    $fingerprint,
            nonceId:        $nonce,
            nonceSigArmor:  $signature,
            claims:         is_array($claims) ? $claims : [],
            claimsSigArmor: $claimsSig,
            publicKeyArmor: $publicKeyArmor,
            challengeCtx:   $challengeCtx,
        );

        if (!$ok) {
            return new JSONResponse(['error' => $err], Http::STATUS_UNAUTHORIZED);
        }

        $uid = $this->keyRegistry->getUid($fingerprint);

        return new JSONResponse([
            'valid'       => true,
            'fingerprint' => $fingerprint,
            'uid'         => $uid,
            'claims'      => is_array($claims) ? $claims : [],
        ]);
    }

    // ── GET /capauth/token/whoami ────────────────────────────────────────────

    /**
     * Returns the fingerprint of the currently authenticated CapAuth session.
     * The PgpVerificationMiddleware sets 'capauth.authenticated_fingerprint'
     * in the session after successful Bearer token auth.
     *
     * @NoCSRFRequired
     */
    public function whoami(): JSONResponse {
        $fp = $this->session->get('capauth.authenticated_fingerprint');
        if ($fp === null) {
            return new JSONResponse(['error' => 'not_authenticated'], Http::STATUS_UNAUTHORIZED);
        }
        $uid = $this->keyRegistry->getUid($fp);
        return new JSONResponse([
            'fingerprint' => $fp,
            'uid'         => $uid,
        ]);
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

    private function decodeToken(string $token): ?array {
        if (str_starts_with(ltrim($token), '{')) {
            $decoded = json_decode($token, true);
        } else {
            $padded  = str_pad(strtr($token, '-_', '+/'), strlen($token) + (4 - strlen($token) % 4) % 4, '=');
            $decoded = json_decode(base64_decode($padded), true);
        }
        return is_array($decoded) ? $decoded : null;
    }

    private function tokenWithinWindow(string $issuedAt): bool {
        if ($issuedAt === '') {
            return false;
        }
        try {
            $issued  = new \DateTimeImmutable($issuedAt);
            $maxAge  = (int) $this->config->getAppValue('capauth', 'token_max_age', '300');
            $cutoff  = new \DateTimeImmutable("now -{$maxAge} seconds");
            return $issued >= $cutoff;
        } catch (\Throwable) {
            return false;
        }
    }
}
