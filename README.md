# TplGuard

A hardened replacement for the template engine used by a legacy PHP forum,
plus an offline scanner and a differential test harness.

It closes the reported vulnerability class — **a moderator who can edit a
post/theme template injects template expressions that execute on the server
(server-side template injection)** — without breaking the thousands of existing
skins and plugins that depend on the old engine's advanced syntax, and without
adding measurable cost to a forum serving millions of requests a day.

```
php examples/demo.php            # the whole story, one run
php bin/tplguard-scan <dir>      # scan an existing skin tree before rollout
./vendor/bin/phpunit             # 100 tests
php benchmarks/render_bench.php  # hot-path cost
```

---

## 1. Why the old engine was exploitable

The legacy engine fed template source through `eval`-like compilation and
allowed, *for every template regardless of who could edit it*:

| Construct | Legacy behaviour | Why it is fatal |
|---|---|---|
| `{php} ... {/php}`, `{eval ...}`, `<!--{eval ...}-->` | inlined as PHP | direct RCE |
| `{system('id')}`, `{file_put_contents(...)}` — any function by name | called | RCE / file write |
| `{$_SERVER...}`, `{$_ENV...}`, `{$GLOBALS...}` | readable | path & secret disclosure, then escalate |
| `{$x|eval:...}` and arbitrary modifiers | PHP callback by name | RCE |
| `{$f(...)}`, `{("sys"."tem")(...)}` | computed callable | RCE |
| `{include $tpl}`, `{template $name}` | any file | local file inclusion |
| `$obj->method()`, `Foo::BAR`, `new Foo` | allowed | gadget chains |

The separator between "theme markup" and "PHP" did not exist. Anyone who could
write a template could run code.

## 2. The fix: capability-based trust tiers

Every template receives a **capability set** derived from server-side facts —
which directory the file lives in and who may write to it — never from anything
inside the template:

| Tier | Root (example) | May edit | Can do |
|---|---|---|---|
| `vendor` | `template/` (shipped, read-only) | nobody | everything, including `{php}` |
| `site` | `data/template/` (installer) | admin | markup, loops, conditionals, **safe** functions/modifiers, plugin tags — **no PHP** |
| `skin` | `data/skin/` (3rd-party / mod) | admin+moderators | as `site`, minimum surface |

`Capabilities` (`src/Security/Capabilities.php`) defines exactly what each tier
grants. A moderator-editable post template lands in `skin`/`site` and simply
**does not possess** `php`, `arbitrary_call`, `dynamic_call`, `static_access`,
`dynamic_include`, or `eval_modifier`. It cannot ask for them; there is no
syntax that expresses them at that tier.

A small, explicit **deny-list** (`Capabilities::DENY_FUNCTIONS`) is checked
*before* any allow-list, so a future edit to the allow-list cannot re-open a
door (`system`, `exec`, `eval`, `file_*`, reflection, `unserialize`, …).
Superglobals are never readable by any template, any tier.

## 3. Why it is not a regex filter

The engine never runs a template that "looks clean". It:

1. **Parses** template source into a closed AST (`src/Parser/`). The grammar is
   not PHP: there is no node for backticks, `?>`, heredoc, variable-variables,
   or a computed callee. Anything that is not expressible as an AST node is
   literal text (`{color:red}` in CSS stays CSS).
2. **Analyses** the AST against the tier's capabilities (`src/Security/Analyzer.php`).
3. **Compiles** to PHP *only* from that AST, with a second capability check at
   emit time (`src/Compiler/Compiler.php`) so an analyzer bug fails closed.

Rejection happens at **compile time**, so a hostile template is never turned
into code — the hot path pays nothing for it. Findings carry rule, line and
source excerpt, so the admin panel can tell the template author exactly which
tag was refused:

```
post.html
  line 2  php.block         Raw PHP blocks are not permitted in this template  | {php} system('id'); {/php}
  line 4  expr.superglobal  Reading $_SERVER is not permitted in any template  | {$_SERVER.HTTP_HOST}
```

## 4. Backwards compatibility (the hard requirement)

The rewrite is only acceptable if every existing skin keeps rendering. That is
enforced, not hoped for:

- **`tests/Support/LegacyReference.php`** is a deliberately naive implementation
  of the *old* semantics (`{$a.b}`, `{if}`, `{loop}`, `echo` behaviour).
- **`tests/LegacyParityTest.php`** renders a corpus of realistic skin templates
  through both engines and asserts **byte-identical** output.
- **`tests/LegacySyntaxTest.php`** locks in 30+ legacy constructs: Discuz
  `<!--{if}-->`/`<!--{loop}-->`, phpwind `[if]`/`[loop]`, `{foreach ... as}`,
  `{foreach from=... item=...}`, `{switch}/{case}`, `{template}`, `{include}`,
  `{tag:...}`, modifier chains, `{$list.0.title}`, ternaries, `{literal}`,
  CSS/JS braces, multiline conditions.

Supported syntax is intentionally broad (see `src/Parser/TemplateParser.php`).
Where a construct is genuinely ambiguous (`$a . $b` — legacy key access vs PHP
concatenation) it is resolved by `ParserOptions::$dotSyntax` (`auto` by
default: `$a.b` is a key, `$a . $b` is concatenation).

**Migration procedure**

1. `php bin/tplguard-scan data/skin --policy=skin` before upgrading. Each hit is
   a template that will be refused; decide per template: rewrite it, or move it
   into the `vendor`/trusted root if it really is trusted code.
2. Move templates that legitimately need PHP into the `vendor` root (read-only,
   deployed with the application — *not* editable from the admin panel).
3. Warm the cache in the deploy step (`Engine::inspect()` / a loop over
   `render()`), so no user request pays the first compile.

## 5. Performance

Compiled artifacts are cached (`src/Cache/CompiledCache.php`) with atomic
`temp + rename()` writes, so a concurrent FPM worker can never `require` a
half-written file. The artifact is a plain PHP class; OPcache serves it.

The in-process `ResolutionIndex` (`src/Cache/ResolutionIndex.php`) notices an
edited template with a single `stat()` (mtime + size) — no source read, no
re-hash, no re-analysis. An edit produces a new key and is re-analysed before
it can render, so "fast" never means "served a stale, un-analysed template".

Measured on PHP 8.5 (this machine):

| | |
|---|---|
| cold compile (parse + analyse + compile + write) | ~2.4 ms, once per template |
| warm render, typical thread template | ~5.6–8 µs |
| throughput, one core | ~120k–180k renders/s |
| overhead vs hand-written PHP | ~2.6–3.5× |
| memory peak | ~4 MB |

A forum at one million page views/day averages **~12 renders per second** — the
engine uses roughly 0.01 % of one core at that load. The 2–3× against inlined
hand-written PHP is the cost of routing every variable read through a guarded
accessor (no `extract()`, no `$$name`, no object magic), which is what makes the
security property hold.

## 6. Integrating with the forum

```php
use TplGuard\Engine;
use TplGuard\Security\TrustPolicy;

$engine = new Engine(
    '/var/www/forum/data/tpl_cache',           // compiled cache dir (writable)
    [
        TrustPolicy::vendor('/var/www/forum/template'),        // shipped skins
        TrustPolicy::site('/var/www/forum/data/template'),     // installer edits
        TrustPolicy::skin('/var/www/forum/data/skin'),         // 3rd-party / mod
    ],
    pluginTags: ['tag:rank' => true],          // registered plugin tags
    tagHandler: fn ($name, $attrs, $body, $ctx) => MyPlugins::render($name, $attrs, $body, $ctx),
);

echo $engine->render('forum/viewthread', ['thread' => $thread, 'posts' => $posts]);
```

The admin/mod template editor must call `$engine->inspect($name)` and show the
findings **before saving**, so a moderator learns immediately that
`{php}`/`{system(...)}` is not available in a post template. `inspect()` never
executes the template.

**Deployment notes**

- Point `TrustPolicy` roots at the *real* directories; trust is by location.
  The template editor must never be able to write into the `vendor` root.
- Ensure the cache dir is writable by the FPM user and is **not** web-served.
- Pin `opcache.validate_timestamps=0` in production and run the warm step on
  deploy; the engine still invalidates correctly, but this is the fastest setup.
- Treat "template refused" as a security event worth logging: it means someone
  tried to use PHP from a template-editable context.

## 7. What is and is not covered

**Covered:** the reported SSTI-to-RCE path (moderator/theme-editor writes
template expressions), all variants in `tests/AttackCorpusTest.php` (39
payloads: `{php}`, `{eval}`, function calls, computed callables, static access,
superglobals, dynamic include, `|eval`, magic methods, …), trust-tier confusion,
path traversal and symlink escape in template lookup.

**Out of scope / still your job:**

- XSS in *data* returned to templates — `|escape` is available and the corpus
  uses it, but this engine does not auto-escape HTML. Escaping is a rendering
  policy decision per template.
- A compromised **admin** account. Admins can publish to the `site` root, which
  still has no PHP — but they can change code elsewhere. The `vendor` root must
  remain outside anything the admin panel can write.
- Vulnerabilities in a plugin's own PHP (`tagHandler`). Plugin tags are treated
  as trusted application code; the analyzer only guarantees the *template* cannot
  feed them arbitrary PHP.

## 8. Layout

```
src/
  Parser/       lexer, expression parser (closed grammar), block parser
  Ast/          expression / statement node types (one class per file)
  Security/     Capabilities, TrustPolicy, Analyzer, Finding
  Compiler/     AST -> PHP class, with fail-closed capability re-checks
  Runtime/      Context (guarded variable access), Renderer, Modifiers, Calls
  Cache/        atomic compiled-artifact cache, stat-based resolution index
  Scanner/      offline skin scanner
  Engine.php    resolve -> compile+cache -> render
bin/tplguard-scan    CLI scanner
examples/demo.php    end-to-end demonstration
tests/               parity, attack corpus, policy, cache, syntax (100 tests)
benchmarks/          hot-path benchmark
```
