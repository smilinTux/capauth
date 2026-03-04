<?php

declare(strict_types=1);

namespace OCA\CapAuth\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Types;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * Creates the oc_capauth_keys table for persistent PGP key storage.
 */
class CreateKeyRegistryTable extends SimpleMigrationStep {
    public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
        /** @var ISchemaWrapper $schema */
        $schema = $schemaClosure();

        if ($schema->hasTable('capauth_keys')) {
            return null;
        }

        $table = $schema->createTable('capauth_keys');

        $table->addColumn('fingerprint', Types::STRING, [
            'length'  => 40,
            'notnull' => true,
        ]);
        $table->addColumn('uid', Types::STRING, [
            'length'  => 64,
            'notnull' => true,
            'default' => '',
        ]);
        $table->addColumn('public_key', Types::TEXT, [
            'notnull' => true,
            'default' => '',
        ]);
        $table->addColumn('approved', Types::SMALLINT, [
            'notnull' => true,
            'default' => 0,
        ]);
        $table->addColumn('linked_to', Types::STRING, [
            'length'  => 40,
            'notnull' => false,
            'default' => null,
        ]);
        $table->addColumn('created_at', Types::STRING, [
            'length'  => 64,
            'notnull' => true,
            'default' => '',
        ]);
        $table->addColumn('last_auth_at', Types::STRING, [
            'length'  => 64,
            'notnull' => false,
            'default' => null,
        ]);

        $table->setPrimaryKey(['fingerprint']);
        $table->addIndex(['uid'], 'capauth_keys_uid_idx');
        $table->addIndex(['approved'], 'capauth_keys_approved_idx');

        return $schema;
    }
}
