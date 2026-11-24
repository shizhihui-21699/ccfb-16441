<?php
declare(strict_types=1);

namespace TplGuard\Tests;

use PHPUnit\Framework\TestCase;
use TplGuard\Engine;
use TplGuard\Security\TrustPolicy;

/**
 * Correctness of the compiled-artifact cache.
 *
 * Two failure modes matter in production:
 *  - a template edit is served stale (a security fix that does not apply), or
 *  - two trust levels share an artifact (a skin render served a vendor-compiled
 *    class with PHP blocks enabled).
 */
final class CacheTest extends TestCase
{
    private string $work;

    protected function setUp(): void
    {
        $this->work = sys_get_temp_dir() . '/tplguard_cache_' . bin2hex(random_bytes(4));
        @mkdir($this->work . '/vendor', 0777, true);
        @mkdir($this->work . '/skin', 0777, true);
    }

    protected function tearDown(): void
    {
        self::rrmdir($this->work);
    }

    private function engine(): Engine
    {
        return new Engine($this->work . '/cache', [
            TrustPolicy::vendor($this->work . '/vendor'),
            TrustPolicy::skin($this->work . '/skin'),
        ]);
    }

    public function testEditIsPickedUpWithinSameProcess(): void
    {
        file_put_contents($this->work . '/vendor/p.html', 'v1');
        $e = $this->engine();
        $this->assertSame('v1', $e->render('p'));

        // Same second, same size: force a distinct mtime is impossible, so we
        // change size too — the stat signature must notice.
        file_put_contents($this->work . '/vendor/p.html', 'version2');
        clearstatcache();
        // The in-process index must invalidate on the stat change.
        $e2 = $this->engine();
        $this->assertSame('version2', $e2->render('p'));
    }

    public function testSameTemplateNameDifferentPolicyDifferentArtifact(): void
    {
        // Identical source in both roots; vendor may use {php}, skin may not.
        $src = 'A{php} echo "B"; {/php}C';
        file_put_contents($this->work . '/vendor/x.html', $src);
        file_put_contents($this->work . '/skin/x.html', $src);

        $vendorEngine = new Engine($this->work . '/cache', [TrustPolicy::vendor($this->work . '/vendor')]);
        $this->assertSame('ABC', $vendorEngine->render('x'));

        $skinEngine = new Engine($this->work . '/cache', [TrustPolicy::skin($this->work . '/skin')]);
        $this->expectException(\TplGuard\Exception\SecurityViolation::class);
        $skinEngine->render('x');
    }

    public function testAtomicWriteLeavesNoTempFiles(): void
    {
        file_put_contents($this->work . '/vendor/a.html', 'hi');
        $this->engine()->render('a');
        $tmp = glob($this->work . '/cache/*/*.tmp') ?: [];
        $this->assertSame([], $tmp, 'atomic rename should leave no temp files');
    }

    public function testArtifactIsValidPhp(): void
    {
        file_put_contents($this->work . '/vendor/b.html', '<p>{$x|escape}</p>{if $x}a{else}b{/if}');
        $this->engine()->render('b', ['x' => '<y>']);
        $artifacts = glob($this->work . '/cache/*/*.php') ?: [];
        $this->assertNotEmpty($artifacts);
        foreach ($artifacts as $f) {
            exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($f) . ' 2>&1', $out, $code);
            $this->assertSame(0, $code, "artifact failed lint: " . implode("\n", $out));
        }
    }

    public function testRepeatedRenderDoesNotRecompile(): void
    {
        file_put_contents($this->work . '/vendor/c.html', '{$n}');
        $e = $this->engine();
        $first = $e->render('c', ['n' => 1]);
        $seen = [];
        foreach (glob($this->work . '/cache/*/*.php') as $f) {
            $seen[$f] = filemtime($f);
        }
        for ($i = 0; $i < 100; $i++) {
            $this->assertSame('1', $e->render('c', ['n' => 1]));
        }
        foreach ($seen as $f => $mtime) {
            clearstatcache(true, $f);
            $this->assertSame($mtime, filemtime($f), 'artifact was rewritten on a warm request');
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
