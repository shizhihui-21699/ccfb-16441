<?php
declare(strict_types=1);

namespace TplGuard\Tests;

use PHPUnit\Framework\TestCase;
use TplGuard\Parser\ParserOptions;
use TplGuard\Parser\TemplateParser;
use TplGuard\Security\Analyzer;
use TplGuard\Security\Capabilities;
use TplGuard\Security\Finding;

/**
 * A template is editable by a moderator, so the *compiler* must not be a
 * denial-of-service vector: an enormous or deeply nested expression must fail
 * fast and cheaply, not exhaust memory or the call stack and kill the worker.
 */
final class ParserDoSTest extends TestCase
{
    /** @dataProvider hostile */
    public function testHostileInputIsBounded(string $name, string $src): void
    {
        $before = memory_get_usage();
        $t0 = microtime(true);

        try {
            $nodes = TemplateParser::parse($src, new ParserOptions());
            (new Analyzer(Capabilities::MINIMAL))->analyze($nodes);
        } catch (\Throwable) {
            // A clean parse error is a fine outcome — the point is that it
            // returns quickly and cheaply rather than OOMing.
        }

        $elapsed = microtime(true) - $t0;
        $delta = memory_get_usage() - $before;
        $this->assertLessThan(1.5, $elapsed, "'$name' took too long to reject");
        $this->assertLessThan(32 * 1024 * 1024, $delta, "'$name' used too much memory");
    }

    public static function hostile(): iterable
    {
        yield 'deep parens' => ['deep parens', '{' . str_repeat('(', 200000) . '1' . str_repeat(')', 200000) . '}'];
        yield 'long concat' => ['long concat', '{' . str_repeat('"A".', 200000) . '"B"}'];
        yield 'many tokens' => ['many tokens', '{' . implode('+', array_fill(0, 100000, '1')) . '}'];
        yield 'deep ternary' => ['deep ternary', '{' . str_repeat('$a ? ', 50000) . '1' . str_repeat(' : 0', 50000) . '}'];
    }

    public function testUnboundedAllocationFunctionsAreNotSafe(): void
    {
        // These would let a tiny template allocate gigabytes at render time.
        foreach (['str_repeat', 'array_fill', 'range', 'array_map', 'array_filter', 'array_reduce'] as $fn) {
            $this->assertFalse(
                Capabilities::isSafeFunction($fn),
                "$fn must not be on the safe-call allow-list"
            );
        }
    }

    public function testCallbackArgumentIsRejected(): void
    {
        $nodes = TemplateParser::parse('{array_map("system",["id"])}', new ParserOptions());
        $a = (new Analyzer(Capabilities::MINIMAL))->analyze($nodes);
        $rules = array_map(fn (Finding $f) => $f->rule, $a->errors());
        $this->assertContains('call.callback', $rules);
        $this->assertContains('call.function', $rules);
    }

    public function testDataEqual_ToFunctionNameIsNotRejected(): void
    {
        // The callback guard must be precise: a value that happens to equal a
        // function name (a user called "system") is ordinary data.
        $dir = sys_get_temp_dir() . '/tplguard_fp_' . bin2hex(random_bytes(4));
        @mkdir($dir, 0777, true);
        file_put_contents($dir . '/p.html', '{strlen($name)}|{implode(",",$tags)}|{$name|trim}');
        try {
            $e = new \TplGuard\Engine($dir . '/c', [\TplGuard\Security\TrustPolicy::site($dir)]);
            $out = $e->render('p', ['name' => 'system', 'tags' => ['system', 'exec']]);
            $this->assertSame('6|system,exec|system', $out);
        } finally {
            @unlink($dir . '/p.html');
            @rmdir($dir);
        }
    }

    public function testLargeTemplateIsStillBounded(): void
    {
        // A big-but-legitimate page must still parse (many rows, not deep).
        $row = '<tr><td>{$row.id}</td><td>{$row.name|escape}</td></tr>';
        $src = str_repeat($row, 20000);
        $t0 = microtime(true);
        $nodes = TemplateParser::parse($src, new ParserOptions());
        $this->assertTrue((new Analyzer(Capabilities::SITE))->analyze($nodes)->ok());
        $this->assertLessThan(3.0, microtime(true) - $t0);
    }
}
