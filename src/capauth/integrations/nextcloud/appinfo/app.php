<?php

declare(strict_types=1);

use OCA\CapAuth\Middleware\PgpVerificationMiddleware;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;

class Application extends App implements IBootstrap {
    public const APP_ID = 'capauth';

    public function __construct() {
        parent::__construct(self::APP_ID);
    }

    public function register(IRegistrationContext $context): void {
        // Register the PGP verification middleware globally so it runs on
        // every controller request and can authenticate Bearer tokens.
        $context->registerMiddleware(PgpVerificationMiddleware::class);
    }

    public function boot(IBootContext $context): void {
        // Nothing additional needed at boot time.
    }
}
