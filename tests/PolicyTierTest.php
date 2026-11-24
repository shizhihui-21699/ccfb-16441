<?php
declare(strict_types=1);

namespace TplGuard\Tests;

use PHPUnit\Framework\TestCase;
use TplGuard\Engine;
use TplGuard\Exception\SecurityViolation;
use TplGuard\Security\Capabilities;
use TplGuard\Security\TrustPolicy;

/**
 * The capability model: the same template source renders under a trusted
 * policy and is refused under a restricted one, and trust is decided by
 * which root the file lives under — never by template content.
 */
final class PolicyTierTest extends TestCase
{
    private static string $work;

    public static function setUpBeforeClass(): void
    {
        self::$work = sys_get_temp_dir() . '/tplguard_pol_' . bin2hex(random_bytes(4));
        @mkdir(self::$work . '/vendor', 0777, true);
        @mkdir(self::$work . '/skin', 0777, true);
        @mkdir(self::$work . '/site', 0777, true);
    }

    public static function tearDownAfterClass(): void
    {
        self::rrmdir(self::$work);
    }

    private function engine(): Engine
    {
        return new Engine(self::$work . '/cache_' . bin2hex(random_bytes(3)), [
            TrustPolicy::vendor(self::$work . '/vendor'),
            TrustPolicy::site(self::$work . '/site'),
            TrustPolicy::skin(self::$work . '/skin'),
        ]);
    }

    public function testVendorTemplateMayUsePhp(): void
    {
        file_put_contents(self::$work . '/vendor/legacy.html', 'before{php} echo strtoupper("mid"); {/php}after');
        $out = $this->engine()->render('legacy');
        $this->assertSame('beforeMIDafter', $out);
    }

    public function testSameSourceIsRefusedInSkinRoot(): void
    {
        $src = 'before{php} echo strtoupper("mid"); {/php}after';
        file_put_contents(self::$work . '/skin/legacy_skin.html', $src);
        $this->expectException(SecurityViolation::class);
        $this->engine()->render('legacy_skin');
    }

    public function testSiteTemplateMayCallSafeFunctions(): void
    {
        file_put_contents(self::$work . '/site/f.html', '{$items|count} / {count($items)}');
        $out = $this->engine()->render('f', ['items' => [1, 2, 3]]);
        $this->assertSame('3 / 3', $out);
    }

    public function testSiteTemplateMayNotCallUnsafeFunctions(): void
    {
        file_put_contents(self::$work . '/site/f.html', '{file_get_contents("/etc/hostname")}');
        $this->expectException(SecurityViolation::class);
        $this->engine()->render('f');
    }

    public function testSkinTemplateMayNotCallEvenSafeFunctionOutsideList(): void
    {
        // MINIMAL grants SAFE_CALLS too, so count() is allowed; but arbitrary
        // calls are not.  `php_uname` is not on the safe list.
        file_put_contents(self::$work . '/skin/f.html', '{php_uname()}');
        $this->expectException(SecurityViolation::class);
        $this->engine()->render('f');
    }

    public function testSameNameInTwoRootsResolvesByPolicyOrder(): void
    {
        file_put_contents(self::$work . '/vendor/same.html', 'VENDOR');
        file_put_contents(self::$work . '/skin/same.html', 'SKIN');
        $this->assertSame('VENDOR', $this->engine()->render('same'));
    }

    public function testTraversalNameRejected(): void
    {
        $this->expectException(\TplGuard\Exception\TemplateException::class);
        $this->engine()->render('../../etc/passwd');
    }

    public function testSymlinkEscapeRejected(): void
    {
        @unlink(self::$work . '/skin/link.html');
        symlink('/etc/hostname', self::$work . '/skin/link.html');
        $this->expectException(\TplGuard\Exception\TemplateException::class);
        $this->engine()->render('link');
    }

    public function testSuperglobalsAreNeverReadable(): void
    {
        // Even a fully trusted template may not read $_SERVER, and even if the
        // caller passes a $_SERVER array in, the runtime refuses to resolve it.
        file_put_contents(self::$work . '/vendor/g.html', '[{$_SERVER.HOSTNAME}]');
        try {
            $this->engine()->render('g', ['_SERVER' => ['HOSTNAME' => 'leak']]);
            $this->fail('superglobal read was not refused');
        } catch (SecurityViolation $e) {
            $rules = array_map(fn ($f) => $f->rule, $e->analysis->errors());
            $this->assertContains('expr.superglobal', $rules);
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
