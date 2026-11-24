<?php
declare(strict_types=1);

namespace TplGuard\Tests;

use PHPUnit\Framework\TestCase;
use TplGuard\Engine;
use TplGuard\Security\ClassAllowList;
use TplGuard\Security\TrustPolicy;

/**
 * Object member access is deny-by-default.  This is the property that stops a
 * template from walking an object graph the controller passed in and reaching
 * a gadget (`$obj->logger->write($cmd)`).
 */
final class MemberAccessTest extends TestCase
{
    private string $work;

    protected function setUp(): void
    {
        $this->work = sys_get_temp_dir() . '/tplguard_mem_' . bin2hex(random_bytes(4));
        @mkdir($this->work . '/site', 0777, true);
    }

    protected function tearDown(): void
    {
        self::rrmdir($this->work);
    }

    private function engine(?ClassAllowList $policy = null): Engine
    {
        return new Engine(
            $this->work . '/cache',
            [TrustPolicy::site($this->work . '/site')],
            memberPolicy: $policy,
        );
    }

    private function tpl(string $src): void
    {
        file_put_contents($this->work . '/site/p.html', $src);
    }

    public function testMethodCallIsDeniedByDefault(): void
    {
        $this->tpl('{$obj->secret()}');
        $out = $this->engine()->render('p', ['obj' => new class {
            public function secret(): string
            {
                return 'leak';
            }
        }]);
        $this->assertSame('', $out);
    }

    public function testPropertyReadIsDeniedByDefault(): void
    {
        $this->tpl('{$obj->path}');
        $out = $this->engine()->render('p', ['obj' => new class {
            public string $path = '/etc/passwd';
        }]);
        $this->assertSame('', $out);
    }

    public function testGadgetChainIsDenied(): void
    {
        $this->tpl('{$obj->evil->run($cmd)}');
        $out = $this->engine()->render('p', [
            'obj' => new class {
                public object $evil;
                public function __construct()
                {
                    $this->evil = new class {
                        public function run(string $c): string
                        {
                            return 'PWNED';
                        }
                    };
                }
            },
            'cmd' => 'id',
        ]);
        $this->assertSame('', $out);
    }

    public function testAllowListGrantsOnlyListedMembers(): void
    {
        $policy = new ClassAllowList(
            methods: [Fixtures\UserView::class => ['getDisplayName']],
            properties: [Fixtures\UserView::class => ['avatarUrl', 'username']],
        );
        $this->tpl('{$u->getDisplayName()}|{$u->avatarUrl}|{$u->password}|{$u->deleteAll()}');
        $out = $this->engine($policy)->render('p', ['u' => new Fixtures\UserView()]);
        // Listed method and property render; the unlisted property and method
        // yield nothing.
        $this->assertSame('Alice|/a.png||', $out);
    }

    public function testCallableArgumentIsRefused(): void
    {
        // A method that would invoke its argument must not receive a callable.
        $policy = new ClassAllowList(methods: [Fixtures\Runner::class => ['run']]);
        $this->tpl('{$r->run($f)}');
        $out = $this->engine($policy)->render('p', [
            'r' => new Fixtures\Runner(),
            'f' => 'system',
        ]);
        // Scalar 'system' is allowed through as a string but cannot execute
        // shell — run() just returns it; the point is no object/callable is
        // passed.  Verify no command ran.
        $this->assertStringNotContainsString('uid=', $out);
    }

    private static function rrmdir(string $dir): void    {
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

final class UserView
{
    public string $username = 'alice';
    public string $avatarUrl = '/a.png';
    public string $password = 'hunter2';

    public function getDisplayName(): string
    {
        return 'Alice';
    }

    public function deleteAll(): string
    {
        return 'deleted';
    }
}

final class Runner
{
    public function run(mixed $arg): string
    {
        if (is_callable($arg)) {
            return (string) $arg('id');
        }
        return 'not-callable';
    }
}
