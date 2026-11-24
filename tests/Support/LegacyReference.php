<?php
declare(strict_types=1);

namespace TplGuard\Tests\Support;

/**
 * A deliberately simple *reference* implementation of the legacy engine's
 * semantics, used as the differential-testing oracle.
 *
 * It is intentionally naive: it resolves `{$a.b}`, `{if}`, `{loop}` with plain
 * PHP array access, and renders output with `echo` semantics.  Tests render
 * the same template through this class and through the hardened engine and
 * assert byte-for-byte equality.  A divergence is either a regression in the
 * new engine or an old behaviour that depended on something unsafe.
 *
 * Test-only.  It is NOT a fallback renderer: it evaluates `{if}` conditions
 * with `eval`.
 */
final class LegacyReference
{
    private int $pos = 0;
    private string $src = '';
    private int $len = 0;

    /** @var array<string,mixed> variable scope, mutable via {assign} */
    private array $vars = [];

    /** @param array<string,mixed> $vars */
    public function render(string $src, array $vars = []): string
    {
        $this->src = $src;
        $this->len = strlen($src);
        $this->pos = 0;
        $this->vars = $vars;
        [$out] = $this->renderNodes($vars, []);
        return $out;
    }

    /**
     * @param array<string,mixed> $vars
     * @param list<string> $stop
     * @return array{0:string,1:?string}
     */
    private function renderNodes(array $vars, array $stop): array
    {
        $out = '';
        while ($this->pos < $this->len) {
            // Stop tags win over anything else at this position.
            $hit = $this->matchStop($stop);
            if ($hit !== null) {
                return [$out, $hit];
            }

            if ($this->startsWith('<!--{') ) {
                $end = strpos($this->src, '}-->', $this->pos);
                if ($end !== false) {
                    $inner = substr($this->src, $this->pos + 5, $end - $this->pos - 5);
                    $this->pos = $end + 4;
                    $out .= $this->renderDiscuz($inner, $vars);
                    continue;
                }
            }

            if ($this->startsWith('{literal}')) {
                $end = stripos($this->src, '{/literal}', $this->pos);
                if ($end !== false) {
                    $out .= substr($this->src, $this->pos + 9, $end - $this->pos - 9);
                    $this->pos = $end + 10;
                    continue;
                }
            }

            $ch = $this->src[$this->pos];
            if (($ch === '{' || $ch === '[') && ($tag = $this->readBalanced($this->pos)) !== null) {
                [$inner, $rawLen] = $tag;
                $trim = trim($inner);
                if ($this->isLegacyTag($trim)) {
                    $this->pos += $rawLen;
                    $out .= $this->renderTag($trim, $this->vars, $trim);
                    continue;
                }
            }

            $out .= $ch;
            $this->pos++;
        }
        return [$out, null];
    }

    /** @param list<string> $stop */
    private function matchStop(array $stop): ?string
    {
        foreach ($stop as $s) {
            if ($this->startsWith($s)) {
                // stop markers are matched as prefixes; the caller consumes.
                $this->pos += strlen($s);
                return $s;
            }
        }
        return null;
    }

    /** Read `{...}` or `[...]` honouring quotes/nesting. @return array{0:string,1:int}|null */
    private function readBalanced(int $at): ?array
    {
        $open = $this->src[$at];
        $close = $open === '{' ? '}' : ']';
        $depth = 0;
        $quote = null;
        for ($i = $at; $i < $this->len; $i++) {
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
            if ($c === $open || ($open === '{' && ($c === '(' || $c === '['))) {
                $depth++;
                continue;
            }
            if ($c === $close || ($close === '}' && ($c === ')' || $c === ']'))) {
                $depth--;
                if ($depth === 0) {
                    return [substr($this->src, $at + 1, $i - $at - 1), $i - $at + 1];
                }
            }
        }
        return null;
    }

    private function isLegacyTag(string $trim): bool
    {
        if ($trim === '') {
            return false;
        }
        if (preg_match('/^(\/)?(if|elseif|else|loop|foreach|assign|include|literal)\b/i', $trim)) {
            return true;
        }
        $c = $trim[0];
        // phpwind writes `[if ...]`; its output tag is `{$var}` style.  A bare
        // `[` here is almost always an array expression or CSS, so only treat
        // `{$`/`{expr}` as output.
        return $c === '$' || $c === '(' || $c === '\'' || $c === '"' || ctype_digit($c);
    }

    private function renderTag(string $inner, array $vars, string $raw): string
    {
        if (preg_match('/^\/if$/i', $inner)) {
            return '';
        }
        if (preg_match('/^\/(loop|foreach)$/i', $inner)) {
            return '';
        }
        if (preg_match('/^(?:else|elseif)\b/i', $inner)) {
            return ''; // handled by the enclosing renderIf
        }
        if (preg_match('/^if\s+([\s\S]+)$/i', $inner, $m)) {
            return $this->renderIf($vars, $m[1]);
        }
        if (preg_match('/^(?:loop|foreach)\s+([\s\S]+)$/i', $inner, $m)) {
            return $this->renderLoop($vars, $m[1]);
        }
        if (preg_match('/^assign\s+var\s*=\s*(\w+)\s+value\s*=\s*([\s\S]+)$/i', $inner, $m)) {
            $this->vars[$m[1]] = $this->evalExpr($m[2], $this->vars);
            return '';
        }
        if (preg_match('/^assign\s+(\w+)\s*=\s*([\s\S]+)$/i', $inner, $m)) {
            $this->vars[$m[1]] = $this->evalExpr($m[2], $this->vars);
            return '';
        }
        if (preg_match('/^assign\s+/i', $inner)) {
            return '';
        }
        if (preg_match('/^include\s+/i', $inner)) {
            return '';
        }
        if ($inner[0] === '$') {
            return $this->renderOutput($inner, $vars);
        }
        return '{' . $inner . '}';
    }

    /**
     * Output tag.  Handles a leading `$var.path` and an optional modifier
     * chain; conditions containing operators are not output tags.
     */
    private function renderOutput(string $expr, array $vars): string
    {
        $expr = trim($expr);
        // Ternary / arithmetic output tags (e.g. {$a ? 'x' : 'y'}) are rare
        // in the reference corpus; evaluate simple ones only.
        if (preg_match('/^\$([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+|\[\d+\])*)(\|.*)?$/s', $expr, $m)) {
            $val = $this->resolvePath($vars, $m[1]);
            if (isset($m[2]) && $m[2] !== '') {
                $val = $this->applyFilters($val, ltrim($m[2], '|'));
            }
            return $this->legacyString($val);
        }
        // A full expression: delegate (used by {$user.admin ? "A" : "u"}).
        return $this->legacyString($this->evalExpr($expr, $vars));
    }

    private function topLevelPipe(string $s): ?int
    {
        $len = strlen($s);
        $depth = 0;
        $quote = null;
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            if ($quote !== null) {
                if ($c === $quote) {
                    $quote = null;
                }
                continue;
            }
            if ($c === '\'' || $c === '"') {
                $quote = $c;
            } elseif ($c === '(' || $c === '[') {
                $depth++;
            } elseif ($c === ')' || $c === ']') {
                $depth--;
            } elseif ($c === '|' && $depth === 0) {
                if (($s[$i + 1] ?? '') === '|') {
                    $i++;
                    continue;
                }
                return $i;
            }
        }
        return null;
    }

    private function renderIf(array $vars, string $cond): string
    {
        // Split the remainder of the if-block into (branch condition, body)
        // segments at this nesting level.
        $depth = 1;
        $p = $this->pos;
        $segments = [];       // list<array{0:?string,1:string}> cond|null for else
        $segments[] = [$cond, ''];
        $bodyStart = $this->pos;
        while ($p < $this->len) {
            $openBrace = $this->src[$p] === '{' ? '{' : ($this->src[$p] === '[' ? '[' : null);
            if ($openBrace !== null) {
                $tag = $this->readBalanced($p);
                if ($tag !== null) {
                    $t = trim($tag[0]);
                    $len = $tag[1];
                    if (preg_match('/^if\b/i', $t)) {
                        $depth++;
                    } elseif (preg_match('/^\/if$/i', $t)) {
                        $depth--;
                        if ($depth === 0) {
                            $segments[count($segments) - 1][1] .= substr($this->src, $bodyStart, $p - $bodyStart);
                            $p += $len;
                            $bodyStart = $p;
                            // Render each taken segment only.
                            $taken = false;
                            $out = '';
                            foreach ($segments as [$c, $segBody]) {
                                if ($c === '' /* else */ ? !$taken : (!$taken && $this->evalCond($vars, $c))) {
                                    $taken = true;
                                    $out .= $this->renderFragment($segBody, $vars);
                                }
                            }
                            $this->pos = $p;
                            return $out;
                        }
                    } elseif ($depth === 1 && preg_match('/^(else|elseif)\b/i', $t)) {
                        $segments[count($segments) - 1][1] .= substr($this->src, $bodyStart, $p - $bodyStart);
                        $rest = preg_replace('/^elseif\s+/i', '', $t);
                        $segments[] = [strcasecmp($rest, 'else') === 0 || !preg_match('/^elseif/i', $t) ? '' : $rest, ''];
                        $p += $len;
                        $bodyStart = $p;
                        continue;
                    }
                    $p += $len;
                    continue;
                }
            }
            $p++;
        }
        // Unclosed: treat the rest as the body.
        $segments[count($segments) - 1][1] .= substr($this->src, $bodyStart);
        $this->pos = $this->len;
        return $this->renderFragment($segments[0][1], $vars);
    }

    /** Render a self-contained fragment (the reference engine is re-entrant enough for this). */
    private function renderFragment(string $fragment, array $vars): string
    {
        $savedSrc = $this->src;
        $savedLen = $this->len;
        $savedPos = $this->pos;
        $savedVars = $this->vars;
        $this->src = $fragment;
        $this->len = strlen($fragment);
        $this->pos = 0;
        $this->vars = $vars;
        [$out] = $this->renderNodes($vars, []);
        $this->src = $savedSrc;
        $this->len = $savedLen;
        $this->pos = $savedPos;
        $this->vars = $savedVars;
        return $out;
    }


    private function renderLoop(array $vars, string $header): string
    {
        $bodyStart = $this->pos;
        $depth = 1;
        $p = $this->pos;
        $endLen = 0;
        $bodyEnd = null;
        while ($p < $this->len) {
            if (preg_match('/\G\{(?:loop|foreach)\s/i', $this->src, $m, 0, $p)) {
                $depth++;
                $p += strlen($m[0]);
                continue;
            }
            if (preg_match('/\G\{\/(?:loop|foreach)\}/i', $this->src, $m, 0, $p)) {
                $depth--;
                if ($depth === 0) {
                    $bodyEnd = $p;
                    $endLen = strlen($m[0]);
                    break;
                }
                $p += strlen($m[0]);
                continue;
            }
            $p++;
        }
        if ($bodyEnd === null) {
            return '';
        }
        $body = substr($this->src, $bodyStart, $bodyEnd - $bodyStart);
        $this->pos = $bodyEnd + $endLen;

        $key = $val = null;
        if (preg_match('/^(\S+)\s+as\s+\$(\w+)\s*=>\s*\$(\w+)$/', trim($header), $mm)) {
            [, $subject, $key, $val] = $mm;
        } elseif (preg_match('/^from\s*=\s*(\S+)\s+item\s*=\s*(\w+)(?:\s+key\s*=\s*(\w+))?$/i', trim($header), $mm)) {
            $subject = $mm[1];
            $val = $mm[2];
            $key = $mm[3] ?? null;
        } elseif (preg_match('/^(\S+)\s+as\s+\$(\w+)$/', trim($header), $mm)) {
            [, $subject, $val] = $mm;
        } elseif (preg_match('/^(\S+)\s+\$(\w+)\s+\$(\w+)$/', trim($header), $mm)) {
            [, $subject, $key, $val] = $mm;
        } elseif (preg_match('/^(\S+)\s+\$(\w+)$/', trim($header), $mm)) {
            [, $subject, $val] = $mm;
        } else {
            return '';
        }
        $list = $this->evalExpr($subject, $vars);
        if (!is_array($list)) {
            return '';
        }
        $out = '';
        $savedSrc = $this->src;
        $savedLen = $this->len;
        $savedPos = $this->pos;
        foreach ($list as $k => $v) {
            $sub = $vars;
            if ($key !== null) {
                $sub[$key] = $k;
            }
            $sub[$val] = $v;
            $savedVars = $this->vars;
            $this->src = $body;
            $this->len = strlen($body);
            $this->pos = 0;
            $this->vars = $sub;
            [$chunk] = $this->renderNodes($sub, []);
            $this->vars = $savedVars;
            $out .= $chunk;
        }
        $this->src = $savedSrc;
        $this->len = $savedLen;
        $this->pos = $savedPos;
        return $out;
    }

    private function renderDiscuz(string $inner, array $vars): string
    {
        $trim = trim($inner);
        if (preg_match('/^\/?(if|loop|foreach)\b/i', $trim)) {
            return ''; // structural handling of comment-tags is out of scope here
        }
        if ($trim !== '' && $trim[0] === '$') {
            return $this->renderOutput($trim, $vars);
        }
        return '';
    }

    /** Resolve `$a.b[0]` / `$a['b']` / bare literals / simple ternaries. */
    private function evalExpr(string $expr, array $vars): mixed
    {
        $expr = trim($expr);
        if ($expr === '') {
            return null;
        }
        // Top-level ternary `a ? b : c`.
        $q = $this->findTopLevel($expr, '?');
        if ($q !== null) {
            $colon = $this->findTopLevelColon($expr, $q + 1);
            if ($colon !== null) {
                $cond = $this->evalExpr(substr($expr, 0, $q), $vars);
                return $cond
                    ? $this->evalExpr(substr($expr, $q + 1, $colon - $q - 1), $vars)
                    : $this->evalExpr(substr($expr, $colon + 1), $vars);
            }
        }
        if ($expr[0] === '$' && preg_match('/^\$[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+|\[\d+\])*$/', $expr)) {
            return $this->resolvePath($vars, substr($expr, 1));
        }
        if (preg_match('/^-?\d+$/', $expr)) {
            return (int) $expr;
        }
        if (preg_match('/^-?\d*\.\d+$/', $expr)) {
            return (float) $expr;
        }
        if (preg_match('/^([\'"])(.*)\1$/s', $expr, $m)) {
            return $m[2];
        }
        if (strcasecmp($expr, 'true') === 0) {
            return true;
        }
        if (strcasecmp($expr, 'false') === 0) {
            return false;
        }
        if (strcasecmp($expr, 'null') === 0) {
            return null;
        }
        // Function call
        if (preg_match('/^([a-zA-Z_][a-zA-Z0-9_]*)\s*\((.*)\)$/s', $expr, $m)) {
            $args = $m[2] === '' ? [] : array_map(fn ($a) => $this->evalExpr($a, $vars), $this->splitArgs($m[2]));
            $fn = strtolower($m[1]);
            return match ($fn) {
                'count', 'sizeof' => is_array($args[0] ?? null) ? count($args[0]) : 0,
                'strlen' => strlen((string) ($args[0] ?? '')),
                'intval' => (int) ($args[0] ?? 0),
                default => null,
            };
        }
        // Binary comparison / concat fallback.
        foreach ([' === ', ' !== ', ' == ', ' != ', ' . ', ' >= ', ' <= ', ' > ', ' < ', ' + ', ' - ', '+', '-'] as $op) {
            $p = strpos($expr, $op);
            if ($p !== false) {
                $l = $this->evalExpr(substr($expr, 0, $p), $vars);
                $r = $this->evalExpr(substr($expr, $p + strlen($op)), $vars);
                return match (trim($op)) {
                    '===' => $l === $r, '!==' => $l !== $r,
                    '==' => $l == $r, '!=' => $l != $r,
                    '.' => $this->legacyString($l) . $this->legacyString($r),
                    '>=' => $l >= $r, '<=' => $l <= $r, '>' => $l > $r, '<' => $l < $r,
                    '+' => $l + $r, '-' => $l - $r,
                    default => null,
                };
            }
        }
        return null;
    }

    private function findTopLevel(string $s, string $needle): ?int
    {
        $depth = 0;
        $quote = null;
        for ($i = 0; $i < strlen($s); $i++) {
            $c = $s[$i];
            if ($quote !== null) {
                if ($c === $quote) {
                    $quote = null;
                }
                continue;
            }
            if ($c === '\'' || $c === '"') {
                $quote = $c;
            } elseif ($c === '(' || $c === '[') {
                $depth++;
            } elseif ($c === ')' || $c === ']') {
                $depth--;
            } elseif ($c === $needle && $depth === 0) {
                return $i;
            }
        }
        return null;
    }

    private function findTopLevelColon(string $s, int $from): ?int
    {
        $depth = 0;
        $quote = null;
        for ($i = $from; $i < strlen($s); $i++) {
            $c = $s[$i];
            if ($quote !== null) {
                if ($c === $quote) {
                    $quote = null;
                }
                continue;
            }
            if ($c === '\'' || $c === '"') {
                $quote = $c;
            } elseif ($c === '(' || $c === '[') {
                $depth++;
            } elseif ($c === ')' || $c === ']') {
                $depth--;
            } elseif ($c === ':' && $depth === 0) {
                // skip `::`
                if (($s[$i - 1] ?? '') === ':' || ($s[$i + 1] ?? '') === ':') {
                    continue;
                }
                return $i;
            }
        }
        return null;
    }

    /** @return list<string> */
    private function splitArgs(string $s): array
    {
        $out = [];
        $depth = 0;
        $quote = null;
        $cur = '';
        for ($i = 0; $i < strlen($s); $i++) {
            $c = $s[$i];
            if ($quote !== null) {
                $cur .= $c;
                if ($c === $quote) {
                    $quote = null;
                }
                continue;
            }
            if ($c === '\'' || $c === '"') {
                $quote = $c;
                $cur .= $c;
            } elseif ($c === '(' || $c === '[') {
                $depth++;
                $cur .= $c;
            } elseif ($c === ')' || $c === ']') {
                $depth--;
                $cur .= $c;
            } elseif ($c === ',' && $depth === 0) {
                $out[] = trim($cur);
                $cur = '';
            } else {
                $cur .= $c;
            }
        }
        if (trim($cur) !== '') {
            $out[] = trim($cur);
        }
        return $out;
    }

    private function resolvePath(array $vars, string $path): mixed
    {
        $path = trim($path, '$');
        $segs = preg_split('/\.|\[|\]/', $path, -1, PREG_SPLIT_NO_EMPTY);
        if (!$segs) {
            return null;
        }
        $v = $vars[array_shift($segs)] ?? null;
        foreach ($segs as $s) {
            $s = trim($s, "'\" ");
            if (is_array($v)) {
                $v = $v[$s] ?? null;
            } elseif (is_object($v)) {
                $v = $v->$s ?? null;
            } else {
                return null;
            }
        }
        return $v;
    }

    private function evalCond(array $vars, string $cond): bool
    {
        $cond = trim($cond);
        $php = preg_replace_callback(
            '/\$([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+|\[[^\]]+\])*)/',
            fn ($m) => '_v(' . var_export($m[1], true) . ')',
            $cond
        );
        $lookup = fn (string $p) => $this->resolvePath($vars, $p);
        return (bool) (static function ($code, $lookup) {
            $fn = function (string $p) use ($lookup) {
                return $lookup($p);
            };
            $code = str_replace('_v(', '$fn(', $php ?? $code);
            return eval('return (' . $code . ');');
        })($php, $lookup);
    }

    private function applyFilters(mixed $v, string $spec): mixed
    {
        foreach (explode('|', $spec) as $f) {
            $f = trim($f);
            if ($f === '') {
                continue;
            }
            $parts = explode(':', $f, 2);
            $name = strtolower(trim($parts[0]));
            $arg = isset($parts[1]) ? trim($parts[1], "'\" ") : null;
            $v = match ($name) {
                'escape', 'e', 'html' => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8'),
                'upper', 'strtoupper' => strtoupper((string) $v),
                'lower', 'strtolower' => strtolower((string) $v),
                'trim' => trim((string) $v),
                'length', 'strlen' => is_array($v) ? count($v) : strlen((string) $v),
                'count' => is_array($v) ? count($v) : 0,
                'nl2br' => nl2br((string) $v),
                'urlencode' => urlencode((string) $v),
                'date' => date((string) ($arg ?? 'Y-m-d'), (int) $v),
                'number_format' => number_format((float) $v, (int) ($arg ?? 0)),
                'raw' => $v,
                'default' => ($v === '' || $v === null) ? $arg : $v,
                default => $v,
            };
        }
        return $v;
    }

    private function legacyString(mixed $v): string
    {
        if (is_array($v)) {
            return 'Array'; // PHP 8 prints "Array" and warns
        }
        if (is_bool($v)) {
            return $v ? '1' : '';
        }
        if ($v === null) {
            return '';
        }
        if (is_float($v) && $v == floor($v) && abs($v) < 1e15) {
            return (string) (int) $v;
        }
        return (string) $v;
    }

    private function startsWith(string $s): bool
    {
        return substr_compare($this->src, $s, $this->pos, strlen($s)) === 0;
    }
}
