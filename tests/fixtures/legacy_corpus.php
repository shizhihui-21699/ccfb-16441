<?php
declare(strict_types=1);

/**
 * Differential corpus: realistic forum skin templates.
 *
 * Each entry is rendered by both the hardened engine and the legacy reference
 * implementation; the test asserts identical output.  These are shaped after
 * Discuz!/phpwind/vBulletin-era skins: nested loops, conditional rows, legacy
 * `.` access, filters, inline ternaries, and `{literal}` blocks.
 */
return [
    'thread row' => [
        'template' => <<<'TPL'
<!-- thread list -->
<div class="thread" id="tid_{$thread.tid}">
  <a href="forum.php?mod=viewthread&tid={$thread.tid}">{$thread.subject|escape}</a>
  {if $thread.sticky}<span class="sticky">[置顶]</span>{/if}
  <span class="author">{$thread.author.username}</span>
  <span class="replies">{$thread.replies}</span>
  <span class="time">{$thread.dateline|date:'Y-m-d'}</span>
</div>
TPL,
        'vars' => [
            'thread' => [
                'tid' => 42,
                'subject' => 'How do I <b>fix</b> this?',
                'sticky' => true,
                'author' => ['username' => 'alice'],
                'replies' => 7,
                'dateline' => 1700000000,
            ],
        ],
    ],

    'post loop with alternation' => [
        'template' => <<<'TPL'
{loop $posts $i $post}
<div class="floor floor-{$i}">
  <div class="content">{$post.message}</div>
  <div class="sig">{$post.author}</div>
</div>
{/loop}
TPL,
        'vars' => [
            'posts' => [
                ['message' => 'first', 'author' => 'bob'],
                ['message' => 'second', 'author' => 'carol'],
                ['message' => 'third', 'author' => 'dave'],
            ],
        ],
    ],

    'nested loop and condition' => [
        'template' => <<<'TPL'
{loop $forums $fid $forum}
<h3>{$forum.name}</h3>
{loop $forum.threads $tid $t}
  {if $t.replies > 100}<b>{$t.title}</b>{else}{$t.title}{/if}
{/loop}
{/loop}
TPL,
        'vars' => [
            'forums' => [
                ['name' => 'General', 'threads' => [
                    ['title' => 'hot', 'replies' => 250],
                    ['title' => 'cold', 'replies' => 3],
                ]],
                ['name' => 'Tech', 'threads' => [
                    ['title' => 'php', 'replies' => 0],
                ]],
            ],
        ],
    ],

    'assign and reuse' => [
        'template' => '{assign var=total value=$a+$b}Total: {$total}',
        'vars' => ['a' => 40, 'b' => 2],
    ],

    'inline ternary and filters' => [
        'template' => '{$user.admin ? "ADMIN" : "user"} / {$name|upper} / {$bio|nl2br}',
        'vars' => ['user' => ['admin' => false], 'name' => 'alice', 'bio' => "line1\nline2"],
    ],

    'literal block protects JS' => [
        'template' => <<<'TPL'
<script>
var cfg = { color: 'red', size: 2 };
</script>
{literal}{$also_literal}{/literal}
<p>{$real}</p>
TPL,
        'vars' => ['real' => 'ok'],
    ],

    'css braces untouched' => [
        'template' => <<<'TPL'
<style>
.box { color: red; margin: 0 auto; }
@media (max-width: 600px) { .box { color: blue } }
</style>
<div class="box">{$text}</div>
TPL,
        'vars' => ['text' => 'hello'],
    ],

    'legacy dot access with numeric index' => [
        'template' => '{$list.0.title} / {$list.1.title}',
        'vars' => ['list' => [
            ['title' => 'one'],
            ['title' => 'two'],
        ]],
    ],

    'boolean and null rendering' => [
        'template' => '[{$t}][{$f}][{$n}][{$i}]',
        'vars' => ['t' => true, 'f' => false, 'n' => null, 'i' => 0],
    ],

    'string concatenation with dot operator' => [
        'template' => '{if $a . $b === "xy"}joined{/if}',
        'vars' => ['a' => 'x', 'b' => 'y'],
    ],

    'comparison chain' => [
        'template' => '{if $views >= 1000 && $locked == false}visible{elseif $views > 0}some{else}none{/if}',
        'vars' => ['views' => 2500, 'locked' => false],
    ],

    'default filter' => [
        'template' => '{$nickname|default:"guest"}',
        'vars' => ['nickname' => ''],
    ],

    'counting a list' => [
        'template' => '{$items|count} items',
        'vars' => ['items' => [1, 2, 3, 4]],
    ],
];
