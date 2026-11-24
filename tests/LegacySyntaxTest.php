<?php
declare(strict_types=1);

namespace TplGuard\Tests;

use PHPUnit\Framework\TestCase;
use TplGuard\Parser\ParserOptions;
use TplGuard\Parser\TemplateParser;
use TplGuard\Security\Analyzer;
use TplGuard\Security\Capabilities;

/**
 * Syntax surface of real forum skins.  Every construct here is something a
 * shipped skin or plugin template uses; all must parse under the SITE policy
 * without a single finding, or the rewrite breaks existing themes.
 */
final class LegacySyntaxTest extends TestCase
{
    /** @dataProvider parses */
    public function testParsesCleanUnderSitePolicy(string $name, string $src): void
    {
        $nodes = TemplateParser::parse($src, new ParserOptions());
        $analysis = (new Analyzer(Capabilities::SITE))->analyze($nodes);
        $this->assertTrue(
            $analysis->ok(),
            "'$name' produced findings: " . implode(', ', array_map(
                fn ($f) => $f->rule . ': ' . $f->message,
                $analysis->errors()
            ))
        );
    }

    public static function parses(): iterable
    {
        $cases = [
            'discuz conditional' => '<!--{if $thread.sticky}-->TOP<!--{/if}-->',
            'discuz loop' => '<!--{loop $list $i $v}-->{$v}<!--{/loop}-->',
            'phpwind conditional' => '[if $x]yes[else]no[/if]',
            'phpwind loop' => '[loop $list $v]{$v}[/loop]',
            'foreach arrow' => '{foreach $list as $k => $v}{$k}={$v}{/foreach}',
            'foreach from' => '{foreach from=$list item=v key=k}{$k}{/foreach}',
            'loop positional' => '{loop $list $k $v}{$v}{/loop}',
            'switch' => '{switch $x}{case 1}one{break}{case 2}two{/switch}',
            'template include' => '{template common/header}',
            'template with params' => '{template common/header title=$t}',
            'include file' => '{include file="common/footer" year=$y}',
            'plugin tag' => '{tag:rank uid=$user.id limit=10}',
            'plugin namespaced' => '{plugin:banner zone=$z}',
            'ad tag' => '{ad:topbanner}',
            'concat in cond' => '{if $a . "x" == "ax"}ok{/if}',
            'modifier chain' => '{$name|trim|upper|escape}',
            'default modifier' => '{$nick|default:"guest"}',
            'modifier with args' => '{$n|number_format:2}',
            'css untouched' => 'body{color:red;margin:0}',
            'js object untouched' => 'var cfg = {a:1,b:2};',
            'multiline condition' => "{if \$a &&\n  \$b}yes{/if}",
            'function call' => '{count($list)}',
            'array literal arg' => '{if in_array($x, [1,2,3])}ok{/if}',
            'legacy numeric dot' => '{$list.0.title}',
            'bracket key' => "{\$a['b']['c']}",
            'ternary output' => '{$admin ? "ADMIN" : "user"}',
            'coalesce' => '{$a ?? "none"}',
            'literal block' => '{literal}{not_a_tag}{/literal}',
            'assign' => '{assign var=total value=$a+$b}{$total}',
            'value list' => '{$a}{$b}{$c}',
        ];
        foreach ($cases as $name => $src) {
            yield $name => [$name, $src];
        }
    }

    public function testDiscuzLoopRenders(): void
    {
        [$out] = $this->render('<!--{loop $list $i $v}-->{$v}-<!--{/loop}-->', ['list' => [1, 2, 3]]);
        $this->assertSame('1-2-3-', $out);
    }

    public function testPhpwindElseRenders(): void
    {
        [$out] = $this->render('[if $a]yes[else]no[/if]', ['a' => false]);
        $this->assertSame('no', $out);
    }

    public function testSwitchRenders(): void
    {
        [$out] = $this->render('{switch $n}{case 1}one{case 2}two{/switch}', ['n' => 2]);
        $this->assertSame('two', $out);
    }

    public function testCssBracesSurvive(): void
    {
        $src = '<style>.a{color:red}.b{color:blue}</style>';
        [$out] = $this->render($src, []);
        $this->assertSame($src, $out);
    }

    /** @return array{0:string} */
    private function render(string $tpl, array $vars): array
    {
        $dir = sys_get_temp_dir() . '/tplguard_syn_' . bin2hex(random_bytes(4));
        @mkdir($dir, 0777, true);
        file_put_contents($dir . '/p.html', $tpl);
        $engine = new \TplGuard\Engine($dir . '/cache', [\TplGuard\Security\TrustPolicy::site($dir)]);
        try {
            return [$engine->render('p', $vars)];
        } finally {
            self::rrmdir($dir);
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
