<?php

declare(strict_types=1);

namespace OCA\CapAuth\BackgroundJob;

use OCA\CapAuth\Db\KeyRegistry;
use OCP\BackgroundJob\IJobList;
use OCP\BackgroundJob\TimedJob;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Hourly background job that cleans up stale state.
 *
 * Currently:
 *   - Nonces are stored in the Nextcloud distributed cache with their own TTL,
 *     so no explicit pruning is needed for nonces.
 *   - This job is reserved for future cleanup tasks (e.g. removing very old
 *     unapproved keys, archiving audit logs, etc).
 *
 * Registered in appinfo/info.xml as a background job.
 */
class PruneExpiredNonces extends TimedJob {
    /** Run once per hour. */
    private const INTERVAL = 3600;

    public function __construct(
        ITimeFactory          $time,
        private readonly KeyRegistry $keyRegistry,
    ) {
        parent::__construct($time);
        $this->setInterval(self::INTERVAL);
    }

    protected function run($argument): void {
        // Nonces self-expire via the cache TTL — nothing to prune.
        // Future: prune unapproved keys older than configurable threshold.
    }
}
