#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * demo.php — the whole story in one run.
 *
 *   1. A moderator-editable post template containing an SSTI payload is
 *      refused at compile time (nothing executes).
 *   2. The same legacy template without the payload renders identically to
 *      the old engine.
 *   3. A vendor template (trusted) may still use {php}.
 *
 *   php examples/demo.php
 */

$autoload = __DIR__ . '/../vendor/autoload.php';
require is_file($autoload) ? $autoload : __DIR__ . '/../autoload.php';

use TplGuard\Engine;
use TplGuard\Exception\SecurityViolation;
use TplGuard\Security\TrustPolicy;
use TplGuard\Tests\Support\LegacyReference;

$work = sys_get_temp_dir() . '/tplguard_demo_' . getmypid();
@mkdir($work . '/skin', 0777, true);
@mkdir($work . '/vendor', 0777, true);

$line = str_repeat('─', 70);
echo "$line\n1. Moderator edits a post template (skin root, editable)\n$line\n";

$payload = <<<'TPL'
<div class="post">{$post.message}</div>
{php} system('id'); {/php}
TPL;
file_put_contents($work . '/skin/post.html', $payload);
echo $payload . "\n";

$skin = new Engine($work . '/cache', [TrustPolicy::skin($work . '/skin')]);
try {
    $skin->render('post', ['post' => ['message' => 'hello']]);
    echo "!! rendered — NOT protected\n";
} catch (SecurityViolation $e) {
    echo "→ refused at compile time:\n";
    foreach ($e->analysis->errors() as $f) {
        printf("    %-14s line %d  %s\n", $f->rule, $f->line, $f->message);
    }
}

echo "\n$line\n2. A normal legacy template renders byte-identically\n$line\n";

$legacy = <<<'TPL'
<div class="thread">
  <a href="?tid={$thread.tid}">{$thread.subject|escape}</a>
  {if $thread.sticky}[置顶]{/if}
  {loop $posts $i $p}<p>{$i}. {$p.author.username}: {$p.message|nl2br}</p>{/loop}
</div>
TPL;
$vars = [
    'thread' => ['tid' => 7, 'subject' => 'How to <fix> this?', 'sticky' => true],
    'posts' => [
        ['author' => ['username' => 'alice'], 'message' => "hello\nworld"],
        ['author' => ['username' => 'bob'], 'message' => 'second'],
    ],
];
file_put_contents($work . '/skin/thread.html', $legacy);
$hardened = $skin->render('thread', $vars);
$old = (new LegacyReference())->render($legacy, $vars);
echo $hardened . "\n";
printf("→ identical to legacy engine: %s\n", $hardened === $old ? 'yes' : 'NO — investigate');

echo "\n$line\n3. A vendor template may still use PHP (trusted root)\n$line\n";
file_put_contents($work . '/vendor/stats.html', '{php} echo "hosts online: " . (7 * 42); {/php}');
$vendor = new Engine($work . '/cache', [TrustPolicy::vendor($work . '/vendor')]);
echo $vendor->render('stats') . "\n";
echo "→ trusted vendor code still runs\n";
