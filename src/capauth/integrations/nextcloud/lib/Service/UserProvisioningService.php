<?php

declare(strict_types=1);

namespace OCA\CapAuth\Service;

use OCA\CapAuth\Db\KeyRegistry;
use OCA\CapAuth\Service\GroupSyncService;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;

/**
 * Auto-provisions Nextcloud users from CapAuth identity claims.
 *
 * When a valid CapAuth token is presented for the first time, this service:
 *   1. Derives a deterministic Nextcloud UID from the PGP fingerprint.
 *   2. Creates the user if they don't exist (with a random unusable password
 *      since login is passwordless via CapAuth).
 *   3. Updates display name and email from CapAuth claims.
 *   4. Registers the PGP key in the KeyRegistry and auto-approves it when
 *      the "auto_approve" config is enabled (default: false for safety).
 *   5. Triggers group sync so CapAuth teams map to Nextcloud groups.
 *
 * Claim keys follow the CapAuth identity spec:
 *   sub   → Nextcloud UID hint (if present, used after sanitisation)
 *   name  → display name
 *   email → email address
 *   teams → array of team slugs for group sync
 */
class UserProvisioningService {
    private const UID_PREFIX    = 'ca_';
    private const MAX_UID_LEN   = 64;

    public function __construct(
        private readonly IUserManager   $userManager,
        private readonly KeyRegistry    $keyRegistry,
        private readonly GroupSyncService $groupSyncService,
        private readonly IConfig        $config,
        private readonly ILogger        $logger,
    ) {}

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Resolve or create a Nextcloud user for the given CapAuth fingerprint.
     *
     * Returns the IUser on success, or null if provisioning is disabled /
     * the user could not be created.
     */
    public function provisionFromFingerprint(string $fingerprint, array $claims = []): ?IUser {
        $fp = strtoupper(trim($fingerprint));

        // 1. Check if we already know this fingerprint.
        $uid = $this->keyRegistry->getUid($fp);
        if ($uid !== null) {
            $user = $this->userManager->get($uid);
            if ($user !== null) {
                $this->updateUserProfile($user, $claims);
                $this->syncGroups($uid, $claims);
                return $user;
            }
        }

        // 2. Derive a UID.
        $uid = $this->deriveUid($fp, $claims);

        // 3. Check whether auto-provisioning is allowed.
        $autoProvision = $this->config->getAppValue('capauth', 'auto_provision', 'false') === 'true';
        if (!$autoProvision) {
            $this->logger->info("CapAuth: auto_provision disabled; fingerprint {$fp} needs manual registration");
            return null;
        }

        // 4. Create user if absent.
        $user = $this->userManager->get($uid);
        if ($user === null) {
            $user = $this->createUser($uid);
            if ($user === null) {
                return null;
            }
        }

        // 5. Register key in registry.
        $autoApprove    = $this->config->getAppValue('capauth', 'auto_approve', 'false') === 'true';
        $publicKeyArmor = $claims['public_key'] ?? '';
        if ($publicKeyArmor !== '') {
            $this->keyRegistry->register($fp, $uid, $publicKeyArmor);
            if ($autoApprove) {
                $this->keyRegistry->approve($fp);
            }
        }

        // 6. Update profile from claims.
        $this->updateUserProfile($user, $claims);
        $this->syncGroups($uid, $claims);

        return $user;
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    private function deriveUid(string $fp, array $claims): string {
        // Prefer the 'sub' claim from CapAuth identity.
        if (!empty($claims['sub'])) {
            $sanitised = $this->sanitiseUid((string) $claims['sub']);
            if ($sanitised !== '') {
                return substr($sanitised, 0, self::MAX_UID_LEN);
            }
        }
        // Fall back to fingerprint-derived UID: ca_ + last 16 hex chars.
        return self::UID_PREFIX . strtolower(substr($fp, -16));
    }

    private function sanitiseUid(string $raw): string {
        // Nextcloud UIDs: alphanumeric, dots, hyphens, underscores, @.
        return preg_replace('/[^a-zA-Z0-9._@\-]/', '', $raw) ?? '';
    }

    private function createUser(string $uid): ?IUser {
        try {
            // Passwordless user: set a random 64-char password; CapAuth auth bypasses it.
            $password = bin2hex(random_bytes(32));
            $user     = $this->userManager->createUser($uid, $password);
            $this->logger->info("CapAuth: provisioned user {$uid}");
            return $user ?: null;
        } catch (\Throwable $e) {
            $this->logger->error("CapAuth: failed to create user {$uid}: " . $e->getMessage());
            return null;
        }
    }

    private function updateUserProfile(IUser $user, array $claims): void {
        if (!empty($claims['name'])) {
            $user->setDisplayName((string) $claims['name']);
        }
        if (!empty($claims['email'])) {
            $user->setEMailAddress((string) $claims['email']);
        }
    }

    private function syncGroups(string $uid, array $claims): void {
        if (empty($claims['teams']) || !is_array($claims['teams'])) {
            return;
        }
        $this->groupSyncService->syncUserTeams($uid, $claims['teams']);
    }
}
