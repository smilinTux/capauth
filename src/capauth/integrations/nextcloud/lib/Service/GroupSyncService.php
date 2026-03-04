<?php

declare(strict_types=1);

namespace OCA\CapAuth\Service;

use OCP\IConfig;
use OCP\IGroupManager;
use OCP\ILogger;
use OCP\IUserManager;

/**
 * Synchronises CapAuth team membership with Nextcloud groups.
 *
 * Design
 * ──────
 * CapAuth teams are identified by string slugs (e.g. "sovereign-coders").
 * Each team slug maps 1-to-1 to a Nextcloud group ID using an optional
 * prefix (config key: capauth/group_prefix, default: "capauth_").
 *
 * On every authentication the service:
 *   1. Builds the expected set of Nextcloud groups from the user's current
 *      CapAuth teams.
 *   2. Adds the user to any groups they should be in but aren't.
 *   3. If "strict_sync" is enabled (default: false), removes the user from
 *      any capauth_* groups they are in but no longer belong to.
 *      Strict mode is conservative — it only removes from groups whose names
 *      start with the configured prefix, leaving manually assigned groups
 *      untouched.
 *
 * Nextcloud groups are created on demand if they don't exist.
 *
 * Config keys (app: capauth):
 *   group_prefix   → string  prefix for managed groups (default "capauth_")
 *   strict_sync    → bool    remove from groups when team leaves (default false)
 */
class GroupSyncService {
    private const DEFAULT_PREFIX = 'capauth_';

    public function __construct(
        private readonly IGroupManager $groupManager,
        private readonly IUserManager  $userManager,
        private readonly IConfig       $config,
        private readonly ILogger       $logger,
    ) {}

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Synchronise a Nextcloud user's group membership to match $teams.
     *
     * @param string   $uid   Nextcloud UID
     * @param string[] $teams CapAuth team slugs from identity claims
     */
    public function syncUserTeams(string $uid, array $teams): void {
        $user = $this->userManager->get($uid);
        if ($user === null) {
            $this->logger->warning("CapAuth GroupSync: user {$uid} not found");
            return;
        }

        $prefix       = $this->groupPrefix();
        $targetGroups = $this->slugsToGroupIds($teams, $prefix);

        // Add to all target groups.
        foreach ($targetGroups as $groupId) {
            $group = $this->groupManager->get($groupId);
            if ($group === null) {
                $group = $this->groupManager->createGroup($groupId);
                if ($group === null) {
                    $this->logger->error("CapAuth GroupSync: failed to create group {$groupId}");
                    continue;
                }
                $this->logger->info("CapAuth GroupSync: created group {$groupId}");
            }
            if (!$group->inGroup($user)) {
                $group->addUser($user);
                $this->logger->info("CapAuth GroupSync: added {$uid} to {$groupId}");
            }
        }

        // Strict-mode cleanup: remove from managed groups the user left.
        $strictSync = $this->config->getAppValue('capauth', 'strict_sync', 'false') === 'true';
        if (!$strictSync) {
            return;
        }

        $currentGroups = $this->groupManager->getUserGroupIds($user);
        foreach ($currentGroups as $groupId) {
            if (!str_starts_with($groupId, $prefix)) {
                continue;  // Not a managed group — skip.
            }
            if (!in_array($groupId, $targetGroups, true)) {
                $group = $this->groupManager->get($groupId);
                if ($group !== null) {
                    $group->removeUser($user);
                    $this->logger->info("CapAuth GroupSync: removed {$uid} from {$groupId}");
                }
            }
        }
    }

    /**
     * Return all Nextcloud groups currently managed by CapAuth (prefix-based).
     *
     * @return string[]
     */
    public function listManagedGroups(): array {
        $prefix = $this->groupPrefix();
        $all    = $this->groupManager->search($prefix);
        return array_map(fn($g) => $g->getGID(), $all);
    }

    /**
     * Map a single CapAuth team slug to a Nextcloud group ID.
     */
    public function teamToGroupId(string $teamSlug): string {
        $prefix    = $this->groupPrefix();
        $sanitised = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $teamSlug) ?? $teamSlug;
        return $prefix . $sanitised;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private function groupPrefix(): string {
        return $this->config->getAppValue('capauth', 'group_prefix', self::DEFAULT_PREFIX);
    }

    /** @return string[] */
    private function slugsToGroupIds(array $slugs, string $prefix): array {
        return array_values(array_map(
            fn($s) => $prefix . (preg_replace('/[^a-zA-Z0-9_\-]/', '_', $s) ?? $s),
            array_filter($slugs, fn($s) => is_string($s) && $s !== ''),
        ));
    }
}
