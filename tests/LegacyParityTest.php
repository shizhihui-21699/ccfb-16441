<?php
declare(strict_types=1);

namespace TplGuard\Tests;

use PHPUnit\Framework\TestCase;
use TplGuard\Security\TrustPolicy;
use TplGuard\Tests\Support\Differential;

/**
 * The core promise of the rewrite: every template that rendered before must
 * render byte-for-byte identically after.
 */
final class LegacyParityTest extends TestCase
{
    private static string $work;

    public static function setUpBeforeClass(): void
    {
        self::$work = sys_get_temp_dir() . '/tplguard_parity_' . bin2hex(random_bytes(4));
        @mkdir(self::$work, 0777, true);
    }

    public static function tearDownAfterClass(): void
    {
        self::rrmdir(self::$work);
    }

    /** @dataProvider corpus */
    public function testLegacyTemplateRendersIdentically(string $name, string $template, array $vars): void
    {
        $diff = new Differential(self::$work, TrustPolicy::site(self::$work));
        [$hardened, $legacy] = $diff->run($template, $vars);
        $this->assertSame(
            $legacy,
            $hardened,
            "Template '$name' diverged.\n--- legacy ---\n$legacy\n--- hardened ---\n$hardened"
        );
    }

    public static function corpus(): iterable
    {
        foreach (require __DIR__ . '/fixtures/legacy_corpus.php' as $name => $case) {
            yield $name => [$name, $case['template'], $case['vars']];
        }
    }

    private static function rrmdir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
        }
        @rmdir($dir);
    }
}
