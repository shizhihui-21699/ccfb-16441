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

    public function testIncludeCannotEscalateToAnotherTier(): void
    {
        // A skin template must not be able to `{include}` a vendor template
        // (which would run with PHP enabled). Includes inherit the includer's
        // resolved policy, so the vendor template is simply not found.
        file_put_contents(self::$work . '/vendor/php_partial.html', '{php} echo "RCE"; {/php}');
        file_put_contents(self::$work . '/skin/uses_partial.html', '{include file="php_partial"}');
        $this->expectException(\TplGuard\Exception\TemplateException::class);
        $this->engine()->render('uses_partial');
    }

    public function testSameTierIncludeWorks(): void
    {
        file_put_contents(self::$work . '/site/frag.html', '<b>{$name}</b>');
        file_put_contents(self::$work . '/site/page.html', 'A{include file="frag"}B');
        $this->assertSame('A<b>x</b>B', $this->engine()->render('page', ['name' => 'x']));
    }

    public function testSelfIncludeIsStoppedByDepthLimit(): void
    {
        // A moderator-editable template must not be able to include itself
        // forever and exhaust the worker's memory.
        file_put_contents(self::$work . '/skin/loop.html', 'A{include file="loop"}');
        $this->expectException(\TplGuard\Exception\TemplateException::class);
        $this->engine()->render('loop');
    }

    public function testObjectIsNeverReachableThroughModifiersOrFunctions(): void
    {
        // An object handed to a template must not leak public state or invoke
        // magic methods (JsonSerializable, __toString, Countable) through an
        // allow-listed function or modifier.
        $gadget = new Fixtures\TemplateGadget();
        file_put_contents(
            self::$work . '/site/gadget_probe.html',
            '[{$o|json}][{json_encode($o)}][{$o}][{$o|count}]'
        );
        $out = $this->engine()->render('gadget_probe', ['o' => $gadget]);
        $this->assertStringNotContainsString('TOPSECRET', $out);
        $this->assertStringNotContainsString('uid=', $out);
        $this->assertStringNotContainsString('PWNED', $out);
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

namespace TplGuard\Tests\Fixtures;

/** A hostile object a controller might (carelessly) pass to a template. */
final class TemplateGadget implements \JsonSerializable, \Stringable, \Countable
{
    public string $secret = 'TOPSECRET';

    public function jsonSerialize(): mixed
    {
        return 'uid=' . (string) shell_exec('id -u');
    }

    public function __toString(): string
    {
        return 'PWNED';
    }

    public function count(): int
    {
        return 42;
    }
}
