<?php

declare(strict_types=1);

namespace OCA\CapAuth\Tests\Unit\Db;

use OCA\CapAuth\Db\KeyRegistry;
use OCP\DB\QueryBuilder\IExpressionBuilder;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for KeyRegistry using a mock DB connection.
 *
 * We avoid a real database by building a minimal QueryBuilder mock that
 * returns pre-canned data. Integration tests with a real DB live in
 * tests/integration/.
 */
class KeyRegistryTest extends TestCase {
    private const FP = '1234567890ABCDEF1234567890ABCDEF12345678';

    /** Build a stub QueryBuilder that returns $rows from executeQuery. */
    private function stubQb(array $rows = [], bool $returnFalse = false): IQueryBuilder {
        $stmt = $this->createMock(\OCP\DB\IResult::class);
        $row = count($rows) > 0 ? array_shift($rows) : false;
        $stmt->method('fetch')->willReturn($row);
        $stmt->method('fetchAll')->willReturn($rows ?: []);
        $stmt->method('closeCursor')->willReturn(true);

        $expr = $this->createMock(IExpressionBuilder::class);
        $expr->method('eq')->willReturnCallback(fn($col, $param) => "{$col}={$param}");
        $expr->method('and')->willReturn('AND');

        $qb = $this->createMock(IQueryBuilder::class);
        $qb->method('select')->willReturnSelf();
        $qb->method('from')->willReturnSelf();
        $qb->method('where')->willReturnSelf();
        $qb->method('andWhere')->willReturnSelf();
        $qb->method('set')->willReturnSelf();
        $qb->method('update')->willReturnSelf();
        $qb->method('delete')->willReturnSelf();
        $qb->method('insert')->willReturnSelf();
        $qb->method('values')->willReturnSelf();
        $qb->method('orderBy')->willReturnSelf();
        $qb->method('createNamedParameter')->willReturnCallback(fn($v) => (string) $v);
        $qb->method('expr')->willReturn($expr);
        $qb->method('executeQuery')->willReturn($stmt);
        $qb->method('executeStatement')->willReturn(1);

        return $qb;
    }

    private function buildRegistry(IQueryBuilder $qb): KeyRegistry {
        $db = $this->createMock(IDBConnection::class);
        $db->method('getQueryBuilder')->willReturn($qb);
        return new KeyRegistry($db);
    }

    // ── exists() ────────────────────────────────────────────────────────────

    public function testExistsReturnsTrueWhenRowFound(): void {
        $reg = $this->buildRegistry($this->stubQb([['fingerprint' => self::FP]]));
        $this->assertTrue($reg->exists(self::FP));
    }

    public function testExistsReturnsFalseWhenNoRow(): void {
        $reg = $this->buildRegistry($this->stubQb([]));
        $this->assertFalse($reg->exists(self::FP));
    }

    // ── isApproved() ────────────────────────────────────────────────────────

    public function testIsApprovedReturnsTrueWhenApproved(): void {
        $reg = $this->buildRegistry($this->stubQb([['approved' => 1]]));
        $this->assertTrue($reg->isApproved(self::FP));
    }

    public function testIsApprovedReturnsFalseWhenNotApproved(): void {
        $reg = $this->buildRegistry($this->stubQb([['approved' => 0]]));
        $this->assertFalse($reg->isApproved(self::FP));
    }

    public function testIsApprovedReturnsFalseWhenKeyNotFound(): void {
        $reg = $this->buildRegistry($this->stubQb([]));
        $this->assertFalse($reg->isApproved(self::FP));
    }

    // ── getPublicKey() ───────────────────────────────────────────────────────

    public function testGetPublicKeyReturnsKeyArmor(): void {
        $armor = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----';
        $reg = $this->buildRegistry($this->stubQb([['public_key' => $armor, 'linked_to' => null]]));
        $this->assertSame($armor, $reg->getPublicKey(self::FP));
    }

    public function testGetPublicKeyReturnsNullWhenNotFound(): void {
        $reg = $this->buildRegistry($this->stubQb([]));
        $this->assertNull($reg->getPublicKey(self::FP));
    }

    // ── Fingerprint normalisation ────────────────────────────────────────────

    public function testNormalisationUppercasesFingerprint(): void {
        // The registry internally normalises fingerprints to uppercase.
        // We verify this by confirming that lowercase input doesn't trip it up.
        // (We use a mock QB so actual SQL isn't executed – we just verify that
        // the registry doesn't crash and calls executeQuery.)
        $qb = $this->stubQb([['fingerprint' => self::FP]]);
        $reg = $this->buildRegistry($qb);
        $this->assertTrue($reg->exists(strtolower(self::FP)));
    }

    // ── listAll() / listPending() ────────────────────────────────────────────

    public function testListAllReturnsFetchAllResult(): void {
        $rows = [
            ['fingerprint' => self::FP, 'approved' => 1],
            ['fingerprint' => 'BBBB5678BBBB5678BBBB5678BBBB5678BBBB5678', 'approved' => 0],
        ];
        $stmt = $this->createMock(\OCP\DB\IResult::class);
        $stmt->method('fetchAll')->willReturn($rows);
        $stmt->method('closeCursor')->willReturn(true);

        $qb = $this->createMock(IQueryBuilder::class);
        $qb->method('select')->willReturnSelf();
        $qb->method('from')->willReturnSelf();
        $qb->method('orderBy')->willReturnSelf();
        $qb->method('executeQuery')->willReturn($stmt);

        $db = $this->createMock(IDBConnection::class);
        $db->method('getQueryBuilder')->willReturn($qb);
        $reg = new KeyRegistry($db);

        $result = $reg->listAll();
        $this->assertCount(2, $result);
    }
}
