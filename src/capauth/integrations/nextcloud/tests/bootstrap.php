<?php

declare(strict_types=1);

/**
 * PHPUnit bootstrap for CapAuth Nextcloud app tests.
 *
 * For unit tests we do NOT need a full Nextcloud stack. We provide minimal
 * stubs for the OCP interfaces used by the app so PHPUnit can autoload them.
 *
 * For integration tests a real Nextcloud instance (or docker compose) is
 * needed — those tests are skipped when NEXTCLOUD_ROOT is not set.
 */

define('CAPAUTH_TEST_ROOT', __DIR__);
define('CAPAUTH_APP_ROOT', dirname(__DIR__));

// ── Composer autoloader ─────────────────────────────────────────────────────
$composerAutoload = CAPAUTH_APP_ROOT . '/vendor/autoload.php';
if (file_exists($composerAutoload)) {
    require_once $composerAutoload;
}

// ── PSR-4 autoloader for the app itself ─────────────────────────────────────
spl_autoload_register(function (string $class): void {
    // Map OCA\CapAuth\… → lib/…
    if (str_starts_with($class, 'OCA\\CapAuth\\')) {
        $relative = str_replace('OCA\\CapAuth\\', '', $class);
        $file = CAPAUTH_APP_ROOT . '/lib/' . str_replace('\\', '/', $relative) . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
        return;
    }

    // Map OCA\CapAuth\Tests\… → tests/…
    if (str_starts_with($class, 'OCA\\CapAuth\\Tests\\')) {
        $relative = str_replace('OCA\\CapAuth\\Tests\\', '', $class);
        $file = CAPAUTH_TEST_ROOT . '/' . str_replace('\\', '/', $relative) . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
        return;
    }
});

// ── Minimal OCP stubs ────────────────────────────────────────────────────────
// These stubs satisfy interface type-hints in unit tests without needing the
// full Nextcloud source tree.  Only the interfaces actually used are stubbed.

if (!interface_exists('OCP\ICache')) {
    interface_exists('OCP\ICache') || eval('namespace OCP; interface ICache { public function get(string $key); public function set(string $key, $value, int $ttl = 0): bool; public function remove(string $key): bool; }');
}
if (!interface_exists('OCP\IConfig')) {
    eval('namespace OCP; interface IConfig { public function getAppValue(string $appId, string $key, string $default = ""): string; public function setAppValue(string $appId, string $key, string $value): void; }');
}
if (!interface_exists('OCP\ISession')) {
    eval('namespace OCP; interface ISession { public function get(string $key); public function set(string $key, $value): void; public function remove(string $key): void; }');
}
if (!interface_exists('OCP\IUser')) {
    eval('namespace OCP; interface IUser { public function getUID(): string; public function getDisplayName(): string; public function setDisplayName(string $displayName): bool; public function getEMailAddress(): string; public function setEMailAddress(string $mailAddress): void; }');
}
if (!interface_exists('OCP\ILogger')) {
    eval('namespace OCP; interface ILogger { public function info(string $message, array $context = []): void; public function warning(string $message, array $context = []): void; public function error(string $message, array $context = []): void; }');
}
if (!interface_exists('OCP\IL10N')) {
    eval('namespace OCP; interface IL10N { public function t(string $text, array $parameters = []): string; }');
}
if (!interface_exists('OCP\IURLGenerator')) {
    eval('namespace OCP; interface IURLGenerator { public function linkToRouteAbsolute(string $routeName, array $arguments = []): string; public function imagePath(string $appName, string $file): string; }');
}
if (!interface_exists('OCP\IUserManager')) {
    eval('namespace OCP; interface IUserManager { public function get(string $uid): ?IUser; public function userExists(string $uid): bool; public function createUser(string $uid, string $password); }');
}
if (!interface_exists('OCP\IUserSession')) {
    eval('namespace OCP; interface IUserSession { public function setUser(?IUser $user): void; public function createRememberMeToken(IUser $user): void; }');
}

// OCP\DB stubs
if (!interface_exists('OCP\\DB\\IResult')) {
    eval('namespace OCP\DB; interface IResult { public function fetch(int $fetchMode = 0); public function fetchAll(int $fetchMode = 0): array; public function closeCursor(): bool; }');
}
if (!interface_exists('OCP\\DB\\QueryBuilder\\IQueryBuilder')) {
    eval('
namespace OCP\DB\QueryBuilder;
interface IQueryBuilder {
    const PARAM_BOOL = 5;
    const PARAM_NULL = 0;
    const PARAM_INT  = 1;
    const PARAM_STR  = 2;
    public function select($selects): self;
    public function from(string $from, ?string $alias = null): self;
    public function where(...$predicates): self;
    public function andWhere(...$predicates): self;
    public function set(string $key, $value): self;
    public function update(string $update): self;
    public function delete(string $delete): self;
    public function insert(string $into): self;
    public function values(array $values): self;
    public function orderBy(string $sort, ?string $order = null): self;
    public function createNamedParameter($value, int $type = self::PARAM_STR, ?string $placeHolder = null): string;
    public function expr(): IExpressionBuilder;
    public function executeQuery(): \OCP\DB\IResult;
    public function executeStatement(): int;
}
');
}
if (!interface_exists('OCP\\DB\\QueryBuilder\\IExpressionBuilder')) {
    eval('namespace OCP\DB\QueryBuilder; interface IExpressionBuilder { public function eq($x, $y): string; public function and(...$args): string; }');
}

// OCP\AppFramework stubs (minimal)
if (!class_exists('OCP\\AppFramework\\Controller')) {
    eval('namespace OCP\AppFramework; abstract class Controller { public function __construct(string $appName, \OCP\IRequest $request) {} }');
}
if (!interface_exists('OCP\\IRequest')) {
    eval('namespace OCP; interface IRequest { public function getParam(string $key, $default = null); }');
}
if (!class_exists('OCP\\AppFramework\\Http\\JSONResponse')) {
    eval('
namespace OCP\AppFramework\Http;
class JSONResponse {
    private array $data; private int $status;
    public function __construct(array $data = [], int $status = 200) { $this->data = $data; $this->status = $status; }
    public function getData(): array { return $this->data; }
    public function getStatus(): int { return $this->status; }
}
');
}
if (!class_exists('OCP\\AppFramework\\Http\\TemplateResponse')) {
    eval('
namespace OCP\AppFramework\Http;
class TemplateResponse {
    public function __construct(string $appName, string $template, array $params = [], string $renderAs = "user") {}
}
');
}
if (!class_exists('OCP\\AppFramework\\Http')) {
    eval('namespace OCP\AppFramework; class Http { const STATUS_OK = 200; const STATUS_CREATED = 201; const STATUS_BAD_REQUEST = 400; const STATUS_UNAUTHORIZED = 401; const STATUS_FORBIDDEN = 403; const STATUS_NOT_FOUND = 404; const STATUS_CONFLICT = 409; const STATUS_INTERNAL_SERVER_ERROR = 500; }');
}
if (!interface_exists('OCP\\Authentication\\TwoFactorAuth\\IProvider')) {
    eval('
namespace OCP\Authentication\TwoFactorAuth;
interface IProvider {
    public function getId(): string;
    public function getDisplayName(): string;
    public function getDescription(): string;
    public function beginAuthentication(\OCP\IUser $user, \OCP\ISession $session): \OCP\Template;
    public function verifyChallenge(\OCP\IUser $user, \OCP\ISession $session, string $challenge): bool;
    public function isTwoFactorAuthEnabledForUser(\OCP\IUser $user): bool;
}
');
}
if (!class_exists('OCP\\Template')) {
    eval('namespace OCP; class Template { public function __construct(string $app, string $name) {} public function assign(string $key, $value): void {} }');
}
if (!interface_exists('OCP\\Settings\\ISettings')) {
    eval('namespace OCP\Settings; interface ISettings { public function getForm(): \OCP\AppFramework\Http\TemplateResponse; public function getSection(): string; public function getPriority(): int; }');
}
if (!interface_exists('OCP\\Settings\\IIconSection')) {
    eval('namespace OCP\Settings; interface IIconSection { public function getID(): string; public function getName(): string; public function getPriority(): int; public function getIcon(): string; }');
}
if (!interface_exists('OCP\\IDBConnection')) {
    eval('namespace OCP; interface IDBConnection { public function getQueryBuilder(): \OCP\DB\QueryBuilder\IQueryBuilder; }');
}
// Stubs for GroupSyncService + UserProvisioningService
if (!interface_exists('OCP\\IGroup')) {
    eval('namespace OCP; interface IGroup { public function getGID(): string; public function inGroup(\OCP\IUser $user): bool; public function addUser(\OCP\IUser $user): void; public function removeUser(\OCP\IUser $user): void; }');
}
if (!interface_exists('OCP\\IGroupManager')) {
    eval('namespace OCP; interface IGroupManager { public function get(string $gid): ?\OCP\IGroup; public function createGroup(string $gid): ?\OCP\IGroup; public function search(string $search, ?int $limit = null, ?int $offset = null): array; public function getUserGroupIds(\OCP\IUser $user): array; }');
}
