<?php
declare(strict_types=1);

namespace TplGuard\Parser;

use TplGuard\Ast;

/**
 * Block-level template parser.
 *
 * Recognises the tag dialects found in real-world PHP forum skins:
 *
 *   {$var}  {$var.key}  {$var['k']}  {$var|escape}  {expr}
 *   {if expr} {elseif expr} {else} {/if}
 *   {loop $list $k $v} {/loop}      {foreach $list $k $v} {/foreach}
 *   {switch $x}{case 1}...{/switch}
 *   <!--{if expr}--> ... <!--{/if}-->              (Discuz)
 *   [if expr] ... [/if]                            (phpwind)
 *   {template name} {/template}                    (Discuz sub-template)
 *   {include file="a/b" key=expr}
 *   {tag:rank uid=$user.id} ... {/tag:rank}         (plugin tags)
 *   {literal} ... {/literal}
 *   {php} ... {/php}    <!--{eval ...}-->
 *
 * Unknown `{...}` sequences are preserved verbatim as text so that skins
 * which use braces in CSS/JS keep working.  The parser never treats input as
 * PHP source; `{php}` / `{eval}` blocks are captured as opaque strings and are
 * rejected later by the analyzer for any non-trusted template.
 */
final class TemplateParser
{
    private string $src;
    private int $len;
    private int $pos = 0;
    private int $line = 1;

    /** @var list<Ast\Node> document root */
    private array $nodes = [];

    /**
     * Open block stack.  Each frame is
     *   name  : 'if' | 'loop' | 'foreach' | 'switch' | 'tag:NAME'
     *   node  : the AST node whose body is being filled
     *   bodyIx: which branch index (if) the current body belongs to
     *
     * @var list<array{name:string,node:Ast\Node,bodyIx:int,line:int}>
     */
    private array $open = [];

    public function __construct(
        string $source,
        private ParserOptions $opts,
        /** @var array<string,true> plugin tag names registered by the site */
        private array $knownTags = [],
    ) {
        $this->src = $source;
        $this->len = strlen($source);
    }

    /** @return list<Ast\Node> */
    public static function parse(string $source, ParserOptions $opts, array $knownTags = []): array
    {
        return (new self($source, $opts, $knownTags))->run();
    }

    /** @return list<Ast\Node> */
    private function run(): array
    {
        while ($this->pos < $this->len) {
            if (!$this->consumeTag()) {
                $this->consumeText();
            }
        }
        if ($this->open) {
            $o = end($this->open);
            throw new ParseException(sprintf('Unclosed {%s} block opened on line %d', $o['name'], $o['line']), 0);
        }
        return $this->nodes;
    }

    // ---------------------------------------------------------------------
    // scanning
    // ---------------------------------------------------------------------

    private function consumeText(): void
    {
        // A raw PHP open-tag region is exactly the legacy attack surface: the
        // old engine included compiled output that PHP then executed.  Capture
        // it as a PHP node so the capability check applies.  Skip the search
        // entirely when the template contains no PHP open tag at all (checked
        // once), otherwise it costs a full backward scan per text chunk.
        $hasPhp = $this->hasPhp ??= str_contains($this->src, '<?');
        $php = $hasPhp ? strpos($this->src, '<?', $this->pos) : false;
        if ($php !== false) {
            $starts = [];
            foreach ($this->tagOpeners() as $o) {
                $p = strpos($this->src, $o, $this->pos);
                if ($p !== false) {
                    $starts[] = $p;
                }
            }
            if (!$starts || $php <= min($starts)) {
                if ($php > $this->pos) {
                    $text = substr($this->src, $this->pos, $php - $this->pos);
                    $this->advance($text);
                    $this->emit(new Ast\Text($text));
                    return;
                }
                $end = strpos($this->src, '?>', $php + 2);
                $codeEnd = $end === false ? $this->len : $end + 2;
                $raw = substr($this->src, $this->pos, $codeEnd - $this->pos);
                $this->advance($raw);
                $this->emit(new Ast\PhpNode($raw));
                return;
            }
        }

        $starts = [];
        foreach ($this->tagOpeners() as $o) {
            $p = strpos($this->src, $o, $this->pos);
            if ($p !== false) {
                $starts[] = $p;
            }
        }
        $next = $starts ? min($starts) : $this->len;
        if ($next <= $this->pos) {
            $next = $this->pos + 1; // unparseable opener: advance one char
        }
        $text = substr($this->src, $this->pos, $next - $this->pos);
        $this->advance($text);
        $this->emit(new Ast\Text($text));
    }

    /**
     * Openers actually present in this template.  Scanning for an opener that
     * occurs nowhere is O(remaining length) on every text chunk (because
     * strpos returns false only after reading to the end), which makes a large
     * document quadratic.  Computing the set once up front keeps parsing
     * linear in template size — important for big thread pages.
     *
     * @var list<string>|null
     */
    private ?array $presentOpeners = null;

    /** Whether the source contains a PHP open tag anywhere (computed once). */
    private ?bool $hasPhp = null;

    /** @return list<string> */
    private function tagOpeners(): array
    {
        if ($this->presentOpeners !== null) {
            return $this->presentOpeners;
        }
        $all = [$this->opts->open];
        if ($this->opts->open === '{') {
            $all[] = '<!--{';
            $all[] = '[';
        }
        $present = [];
        foreach ($all as $o) {
            if (str_contains($this->src, $o)) {
                $present[] = $o;
            }
        }
        return $this->presentOpeners = $present ?: [$this->opts->open];
    }

    private function consumeTag(): bool
    {
        $line = $this->line;

        // ---- phpwind style  [if expr] ... [/if] ------------------------
        if ($this->startsWith('[')) {
            $close = strpos($this->src, ']', $this->pos);
            if ($close !== false) {
                $inner = substr($this->src, $this->pos + 1, $close - $this->pos - 1);
                if (preg_match('/^\s*(\/)?(if|elseif|else|loop|foreach)\b/i', $inner, $m)) {
                    $kw = strtolower($m[2]);
                    $rest = trim(substr($inner, strlen($m[0])));
                    $raw = substr($this->src, $this->pos, $close - $this->pos + 1);
                    $this->advance($raw);
                    if ($m[1] === '/') {
                        return $this->closeBlock($kw, $line);
                    }
                    return $this->openOrStep($kw, $rest, $line);
                }
            }
            return false;
        }

        // ---- Discuz comment style  <!--{...}--> ------------------------
        if ($this->startsWith('<!--{')) {
            $close = strpos($this->src, '}-->', $this->pos);
            if ($close === false) {
                return false;
            }
            $inner = substr($this->src, $this->pos + 5, $close - $this->pos - 5);
            $raw = substr($this->src, $this->pos, $close + 4 - $this->pos);
            $this->advance($raw);
            return $this->handleDiscuzTag($inner, $line);
        }

        if (!$this->startsWith($this->opts->open)) {
            return false;
        }

        // ---- { ... } ---------------------------------------------------
        $openLen = strlen($this->opts->open);
        $end = $this->findClosingBrace($this->pos + $openLen);
        if ($end === null) {
            return false;
        }
        $inner = trim(substr($this->src, $this->pos + $openLen, $end - $this->pos - $openLen));
        $raw = substr($this->src, $this->pos, $end + strlen($this->opts->close) - $this->pos);
        if ($inner === '') {
            return false;
        }

        if (preg_match('/^literal$/i', $inner)) {
            $this->advance($raw);
            return $this->handleLiteral();
        }
        if (preg_match('#^/literal$#i', $inner) || preg_match('#^/php$#i', $inner)) {
            return false;
        }
        if (preg_match('/^php$/i', $inner)) {
            $this->advance($raw);
            return $this->handlePhpBlock();
        }
        // Inline form `{php echo 1;}` — some skins use it instead of the
        // block form.  Parsed as an eval node so it is subject to the same
        // capability check (i.e. refused for untrusted templates).
        if (preg_match('/^php[\s=]+([\s\S]+)$/i', $inner, $m)) {
            $this->advance($raw);
            $this->emit(new Ast\EvalNode($m[1]));
            return true;
        }
        if (preg_match('/^eval\s+([\s\S]+)$/i', $inner, $m)) {
            $this->advance($raw);
            $this->emit(new Ast\EvalNode($m[1]));
            return true;
        }

        // Try to interpret the body before consuming it (so failures can
        // re-emit the original text).
        $before = $this->pos;
        $node = $this->parseBraceTag($inner, $line);
        $consumed = $this->pos !== $before;
        if ($node === null) {
            // Not a template construct (CSS rule, JS object, prose).  Emit the
            // original source verbatim — never a cached/stale slice.
            $this->advance($raw);
            $this->emit(new Ast\Text($raw));
            return true;
        }
        if ($node instanceof Ast\Node) {
            // Block-opening nodes were already emitted by the block handler
            // (emit() attaches them before their body is filled); other nodes
            // still need to be appended here.  Either way the tag text itself
            // must be consumed or the scanner would not advance.
            if (!self::isBlockOpenNode($node)) {
                $this->emit($node);
            }
            if (!$consumed) {
                $this->advance($raw);
            }
            return true;
        }
        // A block-closing keyword was handled.
        if (!$consumed) {
            $this->advance($raw);
        }
        return true;
    }

    /**
     * Nodes whose owner (openOrStep) already called emit() so that following
     * statements land inside the block body rather than after it.
     */
    private static function isBlockOpenNode(Ast\Node $n): bool
    {
        return $n instanceof Ast\IfNode || $n instanceof Ast\Loop;
    }

    // ---------------------------------------------------------------------
    // { ... } dialect
    // ---------------------------------------------------------------------

    /**
     * @return Ast\Node|true|null  node to emit, true if handled inline
     *                             (block open/close), null if not a tag
     */
    private function parseBraceTag(string $inner, int $line): Ast\Node|bool|null
    {
        // Control keywords ------------------------------------------------
        if (preg_match('/^(\/?)(if|elseif|else|loop|foreach|switch|case|default|break)(?![a-zA-Z0-9_:])/i', $inner, $m)) {
            $kw = strtolower($m[2]);
            $rest = trim(substr($inner, strlen($m[0])));
            if ($m[1] === '/') {
                $this->closeBlock($kw, $line);
                return true;
            }
            return $this->openOrStep($kw, $rest, $line);
        }

        // {template name} / {template name key=expr} ----------------------
        if (preg_match('/^template\s+([A-Za-z0-9_\/.-]+)(?:\s+([\s\S]+))?$/i', $inner, $m)) {
            $params = isset($m[2]) ? $this->parseNamedParams($m[2], $line) : [];
            $node = new Ast\IncludeNode(new Ast\Literal($m[1]), $params, false, $m[1]);
            $node->line = $line;
            return $node;
        }

        // {include ...} ----------------------------------------------------
        if (preg_match('/^include\s+([\s\S]+)$/i', $inner, $m)) {
            return $this->handleInclude($m[1], $line);
        }

        // {assign name=expr} / {assign var=name value=expr} ---------------
        if (preg_match('/^assign\s+([\s\S]+)$/i', $inner, $m)) {
            return $this->handleAssign($m[1], $line);
        }

        // {block name ...} legacy plugin blocks ---------------------------
        if (preg_match('/^(block|hook|plug-in)\s+([\s\S]+)$/i', $inner, $m)) {
            return $this->handlePluginTag($m[2], $line);
        }

        // {tag:xxx ...} {plugin:xxx attr=...} ----------------------------
        // Only namespaces that unambiguously denote a plugin call.  A bare
        // `name:value` is CSS (`color:red`), not a tag.
        if (preg_match('/^(tag|plugin|ad|advert|hook|block|widget):([a-z][a-z0-9_-]*)(?:\s+([\s\S]+))?$/i', $inner, $m)
            || (isset($this->knownTags[strtolower($inner)]) && preg_match('/^([a-z][a-z0-9_-]*):([a-z][a-z0-9_-]*)(?:\s+([\s\S]+))?$/i', $inner, $m))) {
            $name = strtolower($m[1] . ':' . $m[2]);
            $attrs = isset($m[3]) ? $this->parseNamedParams($m[3], $line) : [];
            $node = new Ast\TagNode($name, $attrs, [], true);
            $node->line = $line;
            return $node;
        }

        // Output / expression --------------------------------------------
        $first = $inner[0];
        $looksLikeExpr = $first === '$' || $first === '(' || $first === '[' || $first === "'"
            || $first === '"' || $first === '!' || $first === '-'
            || ctype_digit($first)
            || preg_match('/^[A-Za-z_][A-Za-z0-9_]*\s*\(/', $inner)
            || preg_match('/^(true|false|null)$/i', $inner);
        if (!$looksLikeExpr) {
            return null; // CSS / JS / prose: literal text
        }
        try {
            $expr = ExpressionParser::parse($inner, $this->opts);
        } catch (ParseException) {
            return null;
        }
        $node = new Ast\Output($expr);
        $node->line = $line;
        return $node;
    }

    private function openOrStep(string $kw, string $rest, int $line): true
    {
        switch ($kw) {
            case 'if':
                $node = new Ast\IfNode([]);
                $node->line = $line;
                $node->branches[] = [ExpressionParser::parse($rest, $this->opts), []];
                $this->emit($node); // attach to parent before opening its body
                $this->open[] = ['name' => 'if', 'node' => $node, 'bodyIx' => 0, 'line' => $line];
                return true;

            case 'elseif':
                $frame = $this->requireTop('if', $line);
                /** @var Ast\IfNode $if */
                $if = $frame['node'];
                $if->branches[] = [ExpressionParser::parse($rest, $this->opts), []];
                $this->open[count($this->open) - 1]['bodyIx'] = count($if->branches) - 1;
                return true;

            case 'else':
                $frame = $this->requireTop('if', $line);
                $this->open[count($this->open) - 1]['bodyIx'] = -1; // else body
                return true;

            case 'loop':
            case 'foreach':
                $node = $this->parseLoopHeader($rest, $kw, $line);
                $this->emit($node);
                $this->open[] = ['name' => $kw, 'node' => $node, 'bodyIx' => 0, 'line' => $line];
                return true;

            case 'switch':
                $node = new Ast\IfNode([]);
                $node->line = $line;
                $node->switchSubject = ExpressionParser::parse($rest, $this->opts);
                $this->emit($node);
                $this->open[] = ['name' => 'switch', 'node' => $node, 'bodyIx' => 0, 'line' => $line];
                return true;

            case 'case':
                $frame = $this->requireTop('switch', $line);
                /** @var Ast\IfNode $if */
                $if = $frame['node'];
                $case = ExpressionParser::parse($rest, $this->opts);
                $if->branches[] = [new Ast\Binary('==', $if->switchSubject, $case), []];
                $this->open[count($this->open) - 1]['bodyIx'] = count($if->branches) - 1;
                return true;

            case 'default':
                $frame = $this->requireTop('switch', $line);
                $this->open[count($this->open) - 1]['bodyIx'] = -1;
                return true;

            case 'break':
                return true;
        }
        return true;
    }

    private function parseLoopHeader(string $rest, string $kw, int $line): Ast\Loop
    {
        // {loop $list $k $v} / {loop $list $v} / {foreach $list as $k => $v}
        // {foreach from=$list item=v key=k}
        $subject = $keyVar = $valVar = null;

        if (preg_match('/^from\s*=\s*([\s\S]+?)\s+item\s*=\s*(\w+)(?:\s+key\s*=\s*(\w+))?\s*$/is', $rest, $m)) {
            $subject = ExpressionParser::parse($m[1], $this->opts);
            $valVar = $m[2];
            $keyVar = $m[3] ?? null;
        } elseif (preg_match('/^([\s\S]+?)\s+as\s+\$(\w+)\s*=>\s*\$(\w+)\s*$/is', $rest, $m)) {
            $subject = ExpressionParser::parse($m[1], $this->opts);
            $keyVar = $m[2];
            $valVar = $m[3];
        } elseif (preg_match('/^([\s\S]+?)\s+as\s+\$(\w+)\s*$/is', $rest, $m)) {
            $subject = ExpressionParser::parse($m[1], $this->opts);
            $valVar = $m[2];
        } elseif (preg_match('/^([\s\S]+?)\s+\$(\w+)\s+\$(\w+)\s*$/is', $rest, $m)) {
            $subject = ExpressionParser::parse($m[1], $this->opts);
            $keyVar = $m[2];
            $valVar = $m[3];
        } elseif (preg_match('/^([\s\S]+?)\s+\$(\w+)\s*$/is', $rest, $m)) {
            $subject = ExpressionParser::parse($m[1], $this->opts);
            $valVar = $m[2];
        } else {
            throw new ParseException("Malformed {{$kw}} tag: $rest", $line);
        }

        $node = new Ast\Loop($subject, $keyVar, (string) $valVar, []);
        $node->line = $line;
        return $node;
    }

    private function handleInclude(string $rest, int $line): Ast\Node
    {
        if (preg_match('/^file\s*=\s*([\'"])(.*?)\1\s*([\s\S]*)$/is', $rest, $m)) {
            $params = $this->parseNamedParams($m[3], $line);
            $node = new Ast\IncludeNode(new Ast\Literal($m[2]), $params, false, $m[2]);
            $node->line = $line;
            return $node;
        }
        $parts = preg_split('/\s+/', trim($rest), 2);
        $expr = ExpressionParser::parse($parts[0], $this->opts);
        $params = isset($parts[1]) ? $this->parseNamedParams($parts[1], $line) : [];
        $node = new Ast\IncludeNode($expr, $params, true, null);
        $node->line = $line;
        return $node;
    }

    private function handleAssign(string $rest, int $line): Ast\Node
    {
        if (preg_match('/^var\s*=\s*(\w+)\s+value\s*=\s*([\s\S]+)$/is', $rest, $m)) {
            $node = new Ast\AssignNode($m[1], ExpressionParser::parse($m[2], $this->opts));
        } elseif (preg_match('/^(\w+)\s*=\s*([\s\S]+)$/s', $rest, $m)) {
            $node = new Ast\AssignNode($m[1], ExpressionParser::parse($m[2], $this->opts));
        } elseif (preg_match('/^(\w+)\s+([\s\S]+)$/s', $rest, $m)) {
            $node = new Ast\AssignNode($m[1], ExpressionParser::parse($m[2], $this->opts));
        } else {
            throw new ParseException("Malformed {assign}: $rest", $line);
        }
        $node->line = $line;
        return $node;
    }

    private function handlePluginTag(string $rest, int $line): Ast\Node
    {
        $parts = preg_split('/\s+/', trim($rest), 2);
        $name = $parts[0];
        $attrs = isset($parts[1]) ? $this->parseNamedParams($parts[1], $line) : [];
        $node = new Ast\TagNode($name, $attrs, [], true);
        $node->line = $line;
        return $node;
    }

    private function handleDiscuzTag(string $inner, int $line): bool
    {
        $inner = trim($inner);
        if (preg_match('/^(\/?)(if|loop|foreach)(?![a-zA-Z0-9_])/i', $inner, $m)) {
            $kw = strtolower($m[1] === '/' ? $m[2] : $m[2]);
            $rest = trim(substr($inner, strlen($m[0])));
            if ($m[1] === '/') {
                return $this->closeBlock($kw, $line);
            }
            $this->openOrStep($kw, $rest, $line);
            return true;
        }
        if (preg_match('/^eval\s+([\s\S]+)$/i', $inner, $m)) {
            $this->emit(new Ast\EvalNode($m[1]));
            return true;
        }
        if (preg_match('/^(\w+)\s+([\s\S]*)$/', $inner, $m)) {
            $node = new Ast\TagNode($m[1], $this->parseNamedParams($m[2], $line), [], true);
            $node->line = $line;
            $this->emit($node);
            return true;
        }
        try {
            $node = new Ast\Output(ExpressionParser::parse($inner, $this->opts));
            $node->line = $line;
            $this->emit($node);
            return true;
        } catch (ParseException) {
            return false;
        }
    }

    private function handleLiteral(): bool
    {
        $end = stripos($this->src, '{/literal}', $this->pos);
        if ($end === false) {
            throw new ParseException('Unclosed {literal} block', $this->line);
        }
        $text = substr($this->src, $this->pos, $end - $this->pos);
        $this->advance($text);
        $this->advance('{/literal}');
        $this->emit(new Ast\LiteralNode($text));
        return true;
    }

    private function handlePhpBlock(): bool
    {
        $end = stripos($this->src, '{/php}', $this->pos);
        if ($end === false) {
            throw new ParseException('Unclosed {php} block', $this->line);
        }
        $code = substr($this->src, $this->pos, $end - $this->pos);
        $this->advance($code);
        $this->advance('{/php}');
        $this->emit(new Ast\PhpNode($code));
        return true;
    }

    // ---------------------------------------------------------------------
    // block stack
    // ---------------------------------------------------------------------

    /** @return array{name:string,node:Ast\Node,bodyIx:int,line:int} */
    private function requireTop(string $name, int $line): array
    {
        if (!$this->open) {
            throw new ParseException("Unexpected {{$name}} outside a block", $line);
        }
        $top = $this->open[count($this->open) - 1];
        if ($top['name'] !== $name && !($name === 'if' && $top['name'] === 'if')) {
            throw new ParseException("Unexpected {{$name}} inside {{$top['name']}}", $line);
        }
        return $top;
    }

    private function closeBlock(string $kw, int $line): bool
    {
        if (!$this->open) {
            return false;
        }
        $top = $this->open[count($this->open) - 1];
        $ok = match ($kw) {
            'if' => $top['name'] === 'if',
            'loop', 'foreach' => $top['name'] === 'loop' || $top['name'] === 'foreach',
            'switch' => $top['name'] === 'switch',
            'case' => $top['name'] === 'switch',
            default => false,
        };
        if (!$ok) {
            throw new ParseException(sprintf('Unexpected {/%s}; open block is {%s}', $kw, $top['name']), $line);
        }
        array_pop($this->open);
        return true;
    }

    /** @return array */
    private function &currentBody(): array
    {
        if (!$this->open) {
            return $this->nodes;
        }
        $top = &$this->open[count($this->open) - 1];
        $node = $top['node'];
        if ($node instanceof Ast\IfNode) {
            $ix = $top['bodyIx'];
            if ($ix < 0) {
                return $node->else;
            }
            return $node->branches[$ix][1];
        }
        if ($node instanceof Ast\Loop) {
            return $node->body;
        }
        if ($node instanceof Ast\TagNode) {
            return $node->body;
        }
        return $this->nodes;
    }

    private function emit(Ast\Node $node): void
    {
        if ($node->line === 0) {
            $node->line = $this->line;
        }
        $this->stampNode($node);
        $body = &$this->currentBody();
        $body[] = $node;
        unset($body);
    }

    /**
     * Give every expression in a freshly emitted node the current line number
     * (unless it already carries one), so findings point at real source lines.
     */
    private function stampNode(Ast\Node $n): void
    {
        $line = $n->line ?: $this->line;
        if ($n instanceof Ast\Output) {
            self::stampExpr($n->expr, $line);
        } elseif ($n instanceof Ast\IfNode) {
            foreach ($n->branches as [$cond]) {
                self::stampExpr($cond, $line);
            }
        } elseif ($n instanceof Ast\Loop) {
            self::stampExpr($n->subject, $line);
        } elseif ($n instanceof Ast\AssignNode) {
            self::stampExpr($n->value, $line);
        } elseif ($n instanceof Ast\IncludeNode) {
            self::stampExpr($n->file, $line);
        } elseif ($n instanceof Ast\TagNode) {
            foreach ($n->attrs as $e) {
                self::stampExpr($e, $line);
            }
        }
    }

    /**
     * Assign line numbers to an expression tree.  Iterative (explicit stack)
     * so a deeply nested or very wide expression cannot exhaust the call
     * stack — the lexer already caps token count and nesting, but this keeps
     * the walk linear and stack-safe regardless.
     */
    private static function stampExpr(Ast\Expr $root, int $line): void
    {
        $stack = [$root];
        $seen = 0;
        while ($stack) {
            if (++$seen > 50000) {
                return; // hard stop; analysis does not depend on exact lines
            }
            $e = array_pop($stack);
            if (!$e instanceof Ast\Expr) {
                continue;
            }
            if ($e->line === 0) {
                $e->line = $line;
            }
            foreach (self::childExprs($e) as $c) {
                if ($c instanceof Ast\Expr) {
                    $stack[] = $c;
                }
            }
        }
    }

    /** @return list<Ast\Expr> */
    private static function childExprs(Ast\Expr $e): array
    {
        return match (true) {
            $e instanceof Ast\Binary => [$e->left, $e->right],
            $e instanceof Ast\Unary => [$e->operand],
            $e instanceof Ast\Ternary => array_values(array_filter([$e->cond, $e->then, $e->else])),
            $e instanceof Ast\Coalesce => [$e->left, $e->right],
            $e instanceof Ast\Index => [$e->base, $e->key],
            $e instanceof Ast\Prop => [$e->base],
            $e instanceof Ast\MethodCall => array_merge([$e->base], $e->args),
            $e instanceof Ast\FilterExpr => array_merge([$e->base], $e->args),
            $e instanceof Ast\Call => $e->args,
            $e instanceof Ast\DynamicCall => array_merge([$e->callee], $e->args),
            $e instanceof Ast\VarRef => array_values(array_map(
                fn ($p) => $p[1],
                array_filter($e->path, fn ($p) => $p[0] === 'expr')
            )),
            $e instanceof Ast\ArrayLit => self::flattenItems($e->items),
            default => [],
        };
    }

    /** @param list<array{0:?Ast\Expr,1:Ast\Expr}> $items */
    private static function flattenItems(array $items): array
    {
        $out = [];
        foreach ($items as [$k, $v]) {
            if ($k instanceof Ast\Expr) {
                $out[] = $k;
            }
            $out[] = $v;
        }
        return $out;
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    /** @return array<string, Ast\Expr> */
    private function parseNamedParams(string $s, int $line): array
    {
        $out = [];
        $s = trim($s);
        $i = 0;
        $n = strlen($s);
        while ($i < $n) {
            while ($i < $n && ctype_space($s[$i])) {
                $i++;
            }
            if ($i >= $n) {
                break;
            }
            if (!preg_match('/\G([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*/', $s, $m, 0, $i)) {
                break;
            }
            $key = $m[1];
            $i += strlen($m[0]);
            $start = $i;
            $depth = 0;
            $quote = null;
            while ($i < $n) {
                $ch = $s[$i];
                if ($quote !== null) {
                    if ($ch === '\\') {
                        $i += 2;
                        continue;
                    }
                    if ($ch === $quote) {
                        $quote = null;
                    }
                    $i++;
                    continue;
                }
                if ($ch === '\'' || $ch === '"') {
                    $quote = $ch;
                    $i++;
                    continue;
                }
                if ($ch === '(' || $ch === '[') {
                    $depth++;
                } elseif ($ch === ')' || $ch === ']') {
                    $depth--;
                } elseif (ctype_space($ch) && $depth <= 0) {
                    break;
                }
                $i++;
            }
            $valueSrc = substr($s, $start, $i - $start);
            if ($valueSrc === '') {
                $out[$key] = new Ast\Literal(true);
                continue;
            }
            $out[$key] = ExpressionParser::parse($valueSrc, $this->opts);
        }
        return $out;
    }

    private function findClosingBrace(int $from): ?int
    {
        $depth = 0;
        $quote = null;
        for ($i = $from; $i < $this->len; $i++) {
            $c = $this->src[$i];
            if ($quote !== null) {
                if ($c === '\\') {
                    $i++;
                    continue;
                }
                if ($c === $quote) {
                    $quote = null;
                }
                continue;
            }
            if ($c === '\'' || $c === '"') {
                $quote = $c;
                continue;
            }
            if ($c === '{' || $c === '(' || $c === '[') {
                $depth++;
                continue;
            }
            if ($c === '}' || $c === ')' || $c === ']') {
                if ($depth === 0) {
                    return $i;
                }
                $depth--;
            }
        }
        return null;
    }

    private function startsWith(string $s): bool
    {
        return substr_compare($this->src, $s, $this->pos, strlen($s)) === 0;
    }

    private function advance(string $s): void
    {
        if ($s === '') {
            return;
        }
        $this->line += substr_count($s, "\n");
        $this->pos += strlen($s);
    }
}
