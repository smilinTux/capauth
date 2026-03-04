<?php

declare(strict_types=1);

namespace OCA\CapAuth\Middleware;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Service\UserProvisioningService;
use OCA\CapAuth\Service\VerifierService;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Middleware;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;

/**
 * Middleware that authenticates CapAuth Bearer tokens on every request.
 *
 * A CapAuth Bearer token is a base64url-encoded JSON envelope:
 * {
 *   "fingerprint":  "AABB...",
 *   "nonce":        "<uuid>",
 *   "issued_at":    "<ISO8601>",
 *   "service":      "cloud.example.org",
 *   "signature":    "-----BEGIN PGP SIGNED MESSAGE-----..."
 * }
 *
 * The middleware:
 *   1. Parses and validates the token structure.
 *   2. Checks that the fingerprint is in the approved KeyRegistry.
 *   3. Verifies the PGP signature over the canonical payload.
 *   4. Auto-provisions the Nextcloud user if they don't exist yet.
 *   5. Establishes the Nextcloud session for the authenticated user.
 *
 * Requests without a valid token pass through unchanged (the normal
 * Nextcloud auth stack handles them).  Only routes tagged with
 * @CapAuthRequired will reject unauthenticated requests with 401.
 */
class PgpVerificationMiddleware extends Middleware {
    public function __construct(
        private readonly IRequest                $request,
        private readonly ISession                $session,
        private readonly IUserSession            $userSession,
        private readonly KeyRegistry             $keyRegistry,
        private readonly VerifierService         $verifierService,
        private readonly UserProvisioningService $provisioningService,
        private readonly IConfig                 $config,
        private readonly ILogger                 $logger,
    ) {}

    // ── Middleware hook ──────────────────────────────────────────────────────

    public function beforeController($controller, string $methodName): void {
        $token = $this->extractBearerToken();
        if ($token === null) {
            return;  // No CapAuth token — let normal auth proceed.
        }

        $envelope = $this->decodeToken($token);
        if ($envelope === null) {
            return;  // Malformed token — ignore, other auth may handle.
        }

        $fingerprint = strtoupper(trim($envelope['fingerprint'] ?? ''));
        $nonce       = $envelope['nonce']      ?? '';
        $issuedAt    = $envelope['issued_at']  ?? '';
        $service     = $envelope['service']    ?? '';
        $signature   = $envelope['signature']  ?? '';
        $claims      = $envelope['claims']     ?? [];
        $claimsSig   = $envelope['claims_signature'] ?? '';

        if (!$this->isValidFingerprint($fingerprint) || $nonce === '' || $signature === '') {
            return;
        }

        // Reject tokens that are too old (default: 5 minutes).
        if (!$this->tokenWithinWindow($issuedAt)) {
            $this->logger->warning("CapAuth: token expired for fingerprint {$fingerprint}");
            return;
        }

        // Validate key is registered and approved.
        if (!$this->keyRegistry->isApproved($fingerprint)) {
            $this->logger->warning("CapAuth: fingerprint {$fingerprint} not approved");
            return;
        }

        $publicKeyArmor = $this->keyRegistry->getPublicKey($fingerprint);
        if ($publicKeyArmor === null) {
            return;
        }

        // Build the canonical payload the client signed.
        $expiresAt    = $this->deriveExpiresAt($issuedAt);
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
            $this->logger->warning("CapAuth: token verification failed ({$err}) for {$fingerprint}");
            return;
        }

        // Provision / look up the Nextcloud user.
        $user = $this->provisioningService->provisionFromFingerprint(
            $fingerprint,
            is_array($claims) ? $claims : [],
        );

        if ($user === null) {
            $this->logger->error("CapAuth: could not provision user for {$fingerprint}");
            return;
        }

        $this->keyRegistry->recordAuth($fingerprint);
        $this->userSession->setUser($user);
        $this->session->set('capauth.authenticated_fingerprint', $fingerprint);
    }

    // ── Token parsing helpers ────────────────────────────────────────────────

    private function extractBearerToken(): ?string {
        $header = $this->request->getHeader('Authorization');
        if ($header === null || $header === '') {
            return null;
        }
        if (!str_starts_with($header, 'Bearer ')) {
            return null;
        }
        $token = substr($header, 7);
        return $token !== '' ? $token : null;
    }

    private function decodeToken(string $token): ?array {
        // Support both raw JSON and base64url-encoded JSON.
        if (str_starts_with(ltrim($token), '{')) {
            $decoded = json_decode($token, true);
        } else {
            $padded  = str_pad(strtr($token, '-_', '+/'), strlen($token) + (4 - strlen($token) % 4) % 4, '=');
            $decoded = json_decode(base64_decode($padded), true);
        }
        return is_array($decoded) ? $decoded : null;
    }

    private function isValidFingerprint(string $fp): bool {
        return (bool) preg_match('/^[0-9A-F]{40}$/', $fp);
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

    private function deriveExpiresAt(string $issuedAt): string {
        try {
            $ttl = (int) $this->config->getAppValue('capauth', 'nonce_ttl', '120');
            return (new \DateTimeImmutable($issuedAt))
                ->modify("+{$ttl} seconds")
                ->format(\DateTimeInterface::ATOM);
        } catch (\Throwable) {
            return $issuedAt;
        }
    }

    // ── Exception handler ────────────────────────────────────────────────────

    public function afterException($controller, string $methodName, \Exception $exception): ?JSONResponse {
        if ($exception instanceof \OCA\CapAuth\Exception\CapAuthUnauthorizedException) {
            return new JSONResponse(
                ['error' => $exception->getMessage()],
                Http::STATUS_UNAUTHORIZED,
            );
        }
        return null;
    }
}
