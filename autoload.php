<?php
declare(strict_types=1);

/**
 * Standalone autoloader so the library (and its rewrite/scan tools) can run
 * without Composer installed.  Composer users get vendor/autoload.php instead.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'TplGuard\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $rel = str_replace('\\', '/', substr($class, strlen($prefix)));
    $file = __DIR__ . '/src/' . $rel . '.php';
    if (is_file($file)) {
        require $file;
    }
});
