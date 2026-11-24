<?php
declare(strict_types=1);

/**
 * Micro-benchmark: cost of the hardened engine's hot path.
 *
 *   php benchmarks/render_bench.php [iterations]
 *
 * Reports:
 *   - cold compile (parse + analyse + compile + write) once
 *   - warm render, N iterations (the million-hits-a-day path)
 *   - a legacy-style baseline: plain string interpolation of the same data
 *
 * The warm path should be dominated by `require` (served from OPcache in
 * production) plus the render loop itself; there is no parsing or analysis.
 */
require __DIR__ . '/../vendor/autoload.php';

use TplGuard\Engine;
use TplGuard\Security\TrustPolicy;

$iters = (int) ($argv[1] ?? 20000);
$work = sys_get_temp_dir() . '/tplguard_bench_' . getmypid();
@mkdir($work, 0777, true);

$template = <<<'TPL'
<div class="thread" id="tid_{$thread.tid}">
  <a href="forum.php?mod=viewthread&tid={$thread.tid}">{$thread.subject|escape}</a>
  {if $thread.sticky}<span class="sticky">[置顶]</span>{/if}
  <span class="author">{$thread.author.username}</span>
  <span class="replies">{$thread.replies}</span>
</div>
{loop $posts $i $post}
<div class="floor">{$i}: {$post.message|escape}</div>
{/loop}
TPL;
file_put_contents($work . '/page.html', $template);

$vars = [
    'thread' => [
        'tid' => 42,
        'subject' => 'How do I fix this?',
        'sticky' => true,
        'author' => ['username' => 'alice'],
        'replies' => 7,
    ],
    'posts' => array_map(
        fn ($i) => ['message' => "post number $i with <b>markup</b>"],
        range(1, 10)
    ),
];

$engine = new Engine($work . '/cache', [TrustPolicy::site($work)]);

// --- cold compile ------------------------------------------------------
$t0 = hrtime(true);
$engine->render('page', $vars);
$cold = (hrtime(true) - $t0) / 1e6;

// --- warm render -------------------------------------------------------
// Simulate a fresh worker per request is not possible in-process, so we
// measure the steady-state call, which is what a long-lived FPM worker sees.
$t0 = hrtime(true);
for ($i = 0; $i < $iters; $i++) {
    $engine->render('page', $vars);
}
$warmTotal = (hrtime(true) - $t0) / 1e6;
$perOp = $warmTotal / $iters;

// --- baseline: hand-written PHP doing the same loop ---------------------
$baseline = static function (array $vars): string {
    $o = '<div class="thread" id="tid_' . $vars['thread']['tid'] . '">';
    $o .= '<a href="forum.php?mod=viewthread&tid=' . $vars['thread']['tid'] . '">'
        . htmlspecialchars($vars['thread']['subject'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</a>';
    if ($vars['thread']['sticky']) {
        $o .= '<span class="sticky">[置顶]</span>';
    }
    $o .= '<span class="author">' . $vars['thread']['author']['username'] . '</span>';
    $o .= '<span class="replies">' . $vars['thread']['replies'] . '</span></div>';
    foreach ($vars['posts'] as $i => $post) {
        $o .= '<div class="floor">' . $i . ': '
            . htmlspecialchars($post['message'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</div>';
    }
    return $o;
};
$t0 = hrtime(true);
for ($i = 0; $i < $iters; $i++) {
    $baseline($vars);
}
$basePerOp = ((hrtime(true) - $t0) / 1e6) / $iters;

// --- report ------------------------------------------------------------
printf("iterations          : %d\n", $iters);
printf("cold compile        : %.3f ms\n", $cold);
printf("warm render / op    : %.4f ms  (%.0f ops/s)\n", $perOp, 1000 / $perOp);
printf("hand-written PHP /op: %.4f ms\n", $basePerOp);
printf("overhead vs native  : %.2fx\n", $perOp / $basePerOp);
printf("memory peak         : %.1f MB\n", memory_get_peak_usage(true) / 1048576);
