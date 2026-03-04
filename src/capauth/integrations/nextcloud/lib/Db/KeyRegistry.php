<?php

declare(strict_types=1);

namespace OCA\CapAuth\Db;

use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Persists approved PGP public keys and their association with Nextcloud UIDs.
 *
 * Table: oc_capauth_keys
 *   fingerprint  VARCHAR(40)  PK
 *   uid          VARCHAR(64)  NOT NULL
 *   public_key   TEXT         NOT NULL
 *   approved     TINYINT(1)   DEFAULT 0
 *   linked_to    VARCHAR(40)  NULL  (points to primary key if this is an alias)
 *   created_at   DATETIME     NOT NULL
 *   last_auth_at DATETIME     NULL
 */
class KeyRegistry {
    private const TABLE = 'capauth_keys';

    public function __construct(
        private readonly IDBConnection $db,
    ) {}

    // ── Normalisation ────────────────────────────────────────────────────────

    private function normalise(string $fp): string {
        return strtoupper(trim($fp));
    }

    // ── Existence / approval ─────────────────────────────────────────────────

    public function exists(string $fingerprint): bool {
        $fp  = $this->normalise($fingerprint);
        $qb  = $this->db->getQueryBuilder();
        $qb->select('fingerprint')
           ->from(self::TABLE)
           ->where($qb->expr()->eq('fingerprint', $qb->createNamedParameter($fp)));
        $result = $qb->executeQuery();
        $row    = $result->fetch();
        $result->closeCursor();
        return $row !== false;
    }

    public function isApproved(string $fingerprint): bool {
        $fp  = $this->normalise($fingerprint);
        $qb  = $this->db->getQueryBuilder();
        $qb->select('approved')
           ->from(self::TABLE)
           ->where($qb->expr()->eq('fingerprint', $qb->createNamedParameter($fp)));
        $result = $qb->executeQuery();
        $row    = $result->fetch();
        $result->closeCursor();
        return $row !== false && (bool) $row['approved'];
    }

    /**
     * Returns true when the given Nextcloud UID has at least one approved key.
     */
    public function hasApprovedKey(string $uid): bool {
        $qb = $this->db->getQueryBuilder();
        $qb->select('fingerprint')
           ->from(self::TABLE)
           ->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
           ->andWhere($qb->expr()->eq('approved', $qb->createNamedParameter(1, IQueryBuilder::PARAM_INT)));
        $result = $qb->executeQuery();
        $row    = $result->fetch();
        $result->closeCursor();
        return $row !== false;
    }

    // ── Key retrieval ────────────────────────────────────────────────────────

    /**
     * Returns PGP public key armor, or null if not found.
     * Follows the linked_to chain one level (alias → primary).
     */
    public function getPublicKey(string $fingerprint): ?string {
        $fp  = $this->normalise($fingerprint);
        $qb  = $this->db->getQueryBuilder();
        $qb->select('public_key', 'linked_to')
           ->from(self::TABLE)
           ->where($qb->expr()->eq('fingerprint', $qb->createNamedParameter($fp)));
        $result = $qb->executeQuery();
        $row    = $result->fetch();
        $result->closeCursor();
        if ($row === false) {
            return null;
        }
        if (!empty($row['linked_to'])) {
            return $this->getPublicKey($row['linked_to']);
        }
        return $row['public_key'] ?: null;
    }

    /**
     * Returns the Nextcloud UID linked to a fingerprint, or null.
     */
    public function getUid(string $fingerprint): ?string {
        $fp  = $this->normalise($fingerprint);
        $qb  = $this->db->getQueryBuilder();
        $qb->select('uid')
           ->from(self::TABLE)
           ->where($qb->expr()->eq('fingerprint', $qb->createNamedParameter($fp)));
        $result = $qb->executeQuery();
        $row    = $result->fetch();
        $result->closeCursor();
        return $row !== false ? ($row['uid'] ?: null) : null;
    }

    // ── Listing ──────────────────────────────────────────────────────────────

    public function listAll(): array {
        $qb = $this->db->getQueryBuilder();
        $qb->select('*')
           ->from(self::TABLE)
           ->orderBy('created_at', 'DESC');
        $result = $qb->executeQuery();
        $rows   = $result->fetchAll();
        $result->closeCursor();
        return $rows;
    }

    public function listPending(): array {
        $qb = $this->db->getQueryBuilder();
        $qb->select('*')
           ->from(self::TABLE)
           ->where($qb->expr()->eq('approved', $qb->createNamedParameter(0, IQueryBuilder::PARAM_INT)))
           ->orderBy('created_at', 'ASC');
        $result = $qb->executeQuery();
        $rows   = $result->fetchAll();
        $result->closeCursor();
        return $rows;
    }

    // ── Mutations ────────────────────────────────────────────────────────────

    /**
     * Register a new (pending) key. No-ops if the fingerprint already exists.
     */
    public function register(string $fingerprint, string $uid, string $publicKeyArmor): void {
        $fp = $this->normalise($fingerprint);
        if ($this->exists($fp)) {
            return;
        }
        $qb = $this->db->getQueryBuilder();
        $qb->insert(self::TABLE)
           ->values([
               'fingerprint' => $qb->createNamedParameter($fp),
               'uid'         => $qb->createNamedParameter($uid),
               'public_key'  => $qb->createNamedParameter($publicKeyArmor),
               'approved'    => $qb->createNamedParameter(0, IQueryBuilder::PARAM_INT),
               'linked_to'   => $qb->createNamedParameter(null, IQueryBuilder::PARAM_NULL),
               'created_at'  => $qb->createNamedParameter(
                   (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM)
               ),
           ]);
        $qb->executeStatement();
    }

    public function approve(string $fingerprint): void {
        $fp = $this->normalise($fingerprint);
        $qb = $this->db->getQueryBuilder();
        $qb->update(self::TABLE)
           ->set('approved', $qb->createNamedParameter(1, IQueryBuilder::PARAM_INT))
           ->where($qb->expr()->eq('fingerprint', $qb->createNamedParameter($fp)));
        $qb->executeStatement();
    }

    public function revoke(string $fingerprint): void {
        $fp = $this->normalise($fingerprint);
        $qb = $this->db->getQueryBuilder();
        $qb->delete(self::TABLE)
           ->where($qb->expr()->eq('fingerprint', $qb->createNamedParameter($fp)));
        $qb->executeStatement();
    }

    /**
     * Update the last_auth_at timestamp to now.
     */
    public function recordAuth(string $fingerprint): void {
        $fp = $this->normalise($fingerprint);
        $qb = $this->db->getQueryBuilder();
        $qb->update(self::TABLE)
           ->set('last_auth_at', $qb->createNamedParameter(
               (new \DateTimeImmutable())->format(\DateTimeInterface::ATOM)
           ))
           ->where($qb->expr()->eq('fingerprint', $qb->createNamedParameter($fp)));
        $qb->executeStatement();
    }
}
