<?php
declare(strict_types=1);

namespace TplGuard\Compiler;

use TplGuard\Ast;
use TplGuard\Parser\ParserOptions;
use TplGuard\Security\Analyzer;
use TplGuard\Security\Capabilities;

/**
 * Compiles a parsed AST to a self-contained PHP class.
 *
 * The compiler is the *only* place that emits PHP, and it emits it from a
 * closed set of AST node types.  Every expression is lowered to a call on a
 * runtime helper or to a direct call of a name the analyzer already approved;
 * no template-controlled string ever becomes a function name, class name, or
 * `eval` body at compile time.
 *
 * Defensive duplication: the compiler re-checks capabilities for the few
 * dangerous node types before emitting them, so a bug in the analyzer cannot
 * turn into code execution by itself (the check fails closed).
 */
final class Compiler
{
    private int $indent = 0;
    private int $tmp = 0;

    /** @var list<string> */
    private array $lines = [];

    /**
     * @param list<Ast\Node> $nodes
     * @param list<string>   $caps
     */
    public function __construct(
        private array $nodes,
        private array $caps,
        private ParserOptions $opts,
        private string $className,
        private string $sourceHash,
        private string $templateName,
    ) {}

    public function compile(): string
    {
        $this->emitHeader();
        $this->line('public function render(\\TplGuard\\Runtime\\Context $ctx, \\TplGuard\\Runtime\\Renderer $r): string');
        $this->line('{');
        $this->indent++;
        $this->line('$__out = \'\';');
        $this->compileNodes($this->nodes);
        $this->line('return $__out;');
        $this->indent--;
        $this->line('}');
        $this->line('}');
        return implode("\n", $this->lines) . "\n";
    }

    private function emitHeader(): void
    {
        $this->line('<?php');
        $this->line('declare(strict_types=1);');
        $this->line('// Compiled by TplGuard. Do not edit; regeneration is automatic.');
        $this->line(sprintf('// template: %s', str_replace(['*/', "\n"], '', $this->templateName)));
        $this->line(sprintf('// source-sha256: %s', $this->sourceHash));
        $this->line(sprintf('// capabilities: %s', implode(',', $this->caps)));
        $this->line('namespace TplGuard\\Compiled;');
        $this->line('final class ' . $this->className . ' extends \\TplGuard\\Runtime\\CompiledTemplate');
        $this->line('{');
        $this->indent++;
        $this->line('public const SOURCE_HASH = ' . var_export($this->sourceHash, true) . ';');
        $this->line('public const TEMPLATE_NAME = ' . var_export($this->templateName, true) . ';');
    }

    /** @param list<Ast\Node> $nodes */
    private function compileNodes(array $nodes): void
    {
        foreach ($nodes as $n) {
            $this->compileNode($n);
        }
    }

    private function compileNode(Ast\Node $n): void
    {
        if ($n instanceof Ast\Text) {
            if ($n->text !== '') {
                $this->line('$__out .= ' . var_export($n->text, true) . ';');
            }
            return;
        }
        if ($n instanceof Ast\LiteralNode) {
            $this->line('$__out .= ' . var_export($n->text, true) . ';');
            return;
        }
        if ($n instanceof Ast\Output) {
            $code = $this->expr($n->expr);
            $this->line('$__out .= \\TplGuard\\Runtime\\Renderer::out(' . $code . ');');
            return;
        }
        if ($n instanceof Ast\IfNode) {
            $first = true;
            foreach ($n->branches as [$cond, $body]) {
                $this->line(($first ? 'if' : 'elseif') . ' (' . $this->cond($cond) . ') {');
                $first = false;
                $this->indent++;
                $this->compileNodes($body);
                $this->indent--;
                $this->line('}');
            }
            if ($n->else) {
                $this->line('else {');
                $this->indent++;
                $this->compileNodes($n->else);
                $this->indent--;
                $this->line('}');
            }
            return;
        }
        if ($n instanceof Ast\Loop) {
            $this->compileLoop($n);
            return;
        }
        if ($n instanceof Ast\AssignNode) {
            $this->line(sprintf(
                '$ctx->set(%s, %s);',
                var_export($n->name, true),
                $this->expr($n->value)
            ));
            return;
        }
        if ($n instanceof Ast\IncludeNode) {
            if ($n->dynamic && !Capabilities::has($this->caps, Capabilities::DYNAMIC_INCLUDE)) {
                throw new \LogicException('Dynamic include reached the compiler without capability');
            }
            $params = [];
            foreach ($n->params as $k => $v) {
                $params[] = var_export($k, true) . ' => ' . $this->expr($v);
            }
            $this->line(sprintf(
                '$__out .= $r->include(%s, [%s]);',
                $this->expr($n->file),
                implode(', ', $params)
            ));
            return;
        }
        if ($n instanceof Ast\PhpNode || $n instanceof Ast\EvalNode) {
            if (!Capabilities::has($this->caps, Capabilities::PHP)) {
                throw new \LogicException('Raw PHP reached the compiler without capability');
            }
            // Trusted vendor code only: inlined exactly as the legacy engine
            // would have, inside an output buffer so `echo` is captured.
            // The generated file is already in PHP mode, so the fragment is
            // spliced in directly; if the fragment leaves PHP mode open (a
            // stray close tag) we re-open it so the surrounding code stays valid.
            $code = $n->code;
            if (self::endsInHtmlMode($code)) {
                $code .= '<?php';
            }
            $this->line('$__out .= (static function (\\TplGuard\\Runtime\\Context $ctx, \\TplGuard\\Runtime\\Renderer $r): string {');
            $this->indent++;
            $this->line('ob_start();');
            $this->lines[] = $code;
            $this->line('return (string) ob_get_clean();');
            $this->indent--;
            $this->line('})($ctx, $r);');
            return;
        }
        if ($n instanceof Ast\TagNode) {
            if (!Capabilities::has($this->caps, Capabilities::PLUGIN_TAGS)) {
                throw new \LogicException('Plugin tag reached the compiler without capability');
            }
            $attrs = [];
            foreach ($n->attrs as $k => $v) {
                $attrs[] = var_export($k, true) . ' => ' . $this->expr($v);
            }
            if ($n->body) {
                $this->line('$__body = (static function (\\TplGuard\\Runtime\\Context $ctx, \\TplGuard\\Runtime\\Renderer $r): string {');
                $this->indent++;
                $this->line('$__out = \'\';');
                $this->compileNodes($n->body);
                $this->line('return $__out;');
                $this->indent--;
                $this->line('})($ctx, $r);');
                $this->line(sprintf(
                    '$__out .= $r->tag(%s, [%s], $__body, $ctx);',
                    var_export($n->name, true),
                    implode(', ', $attrs)
                ));
            } else {
                $this->line(sprintf(
                    '$__out .= $r->tag(%s, [%s], null, $ctx);',
                    var_export($n->name, true),
                    implode(', ', $attrs)
                ));
            }
            return;
        }
        throw new \LogicException('Unknown AST node: ' . get_class($n));
    }

    private function compileLoop(Ast\Loop $n): void
    {
        $it = '$__it' . (++$this->tmp);
        $this->line($it . ' = \\TplGuard\\Runtime\\Renderer::iterable(' . $this->expr($n->subject) . ');');

        // Save previous values of the loop variables.
        $valName = $n->valVar;
        $keyName = $n->keyVar;
        $this->line(sprintf(
            '$__sv%d = $ctx->has(%s) ? [true, $ctx->get(%s)] : [false, null];',
            $this->tmp,
            var_export($valName, true),
            var_export($valName, true)
        ));
        if ($keyName !== null) {
            $this->line(sprintf(
                '$__sk%d = $ctx->has(%s) ? [true, $ctx->get(%s)] : [false, null];',
                $this->tmp,
                var_export($keyName, true),
                var_export($keyName, true)
            ));
        }
        $tmpId = $this->tmp;
        $this->line('if (' . $it . ' !== []) {');
        $this->indent++;
        $this->line('foreach (' . $it . ' as $__k' . $tmpId . ' => $__v' . $tmpId . ') {');
        $this->indent++;
        if ($keyName !== null) {
            $this->line(sprintf('$ctx->set(%s, $__k%d);', var_export($keyName, true), $tmpId));
        }
        $this->line(sprintf('$ctx->set(%s, $__v%d);', var_export($valName, true), $tmpId));
        $this->compileNodes($n->body);
        $this->indent--;
        $this->line('}');
        $this->indent--;
        $this->line('}');
        // Restore.
        $this->line(sprintf(
            '$__sv%d[0] ? $ctx->set(%s, $__sv%d[1]) : $ctx->unset(%s);',
            $tmpId,
            var_export($valName, true),
            $tmpId,
            var_export($valName, true)
        ));
        if ($keyName !== null) {
            $this->line(sprintf(
                '$__sk%d[0] ? $ctx->set(%s, $__sk%d[1]) : $ctx->unset(%s);',
                $tmpId,
                var_export($keyName, true),
                $tmpId,
                var_export($keyName, true)
            ));
        }
    }

    private function cond(Ast\Expr $e): string
    {
        return '((bool) (' . $this->expr($e) . '))';
    }

    private function expr(Ast\Expr $e): string
    {
        if ($e instanceof Ast\Literal) {
            return var_export($e->value, true);
        }
        if ($e instanceof Ast\VarRef) {
            $path = [];
            foreach ($e->path as [$kind, $payload]) {
                if ($kind === 'key') {
                    $path[] = var_export($payload, true);
                } else {
                    if (!Capabilities::has($this->caps, Capabilities::DYNAMIC_INDEX)) {
                        throw new \LogicException('Dynamic index reached the compiler without capability');
                    }
                    $path[] = $this->expr($payload);
                }
            }
            return sprintf('$ctx->resolve(%s, [%s])', var_export($e->root, true), implode(', ', $path));
        }
        if ($e instanceof Ast\Index) {
            if (!Capabilities::has($this->caps, Capabilities::DYNAMIC_INDEX)) {
                throw new \LogicException('Dynamic index reached the compiler without capability');
            }
            return sprintf(
                '$ctx->dig(%s, %s)',
                $this->expr($e->base),
                $this->expr($e->key)
            );
        }
        if ($e instanceof Ast\Prop) {
            // Property reads go through the context's member policy — never a
            // bare `->` that could walk into a gadget object.
            return sprintf(
                '$ctx->readProperty(%s, %s)',
                $this->expr($e->base),
                var_export(ltrim($e->name, '$'), true)
            );
        }
        if ($e instanceof Ast\MethodCall) {
            if (!Capabilities::has($this->caps, Capabilities::METHOD_CALL)) {
                throw new \LogicException('Method call reached the compiler without capability');
            }
            $args = array_map(fn (Ast\Expr $a) => $this->expr($a), $e->args);
            return sprintf(
                '$r->callMethod(%s, %s, [%s], $ctx)',
                $this->expr($e->base),
                var_export($e->name, true),
                implode(', ', $args)
            );
        }
        if ($e instanceof Ast\Call) {
            $name = $e->name;
            if (Capabilities::isDeniedFunction($name)) {
                throw new \LogicException("Denied function $name reached the compiler");
            }
            $args = array_map(fn (Ast\Expr $a) => $this->expr($a), $e->args);
            if (Capabilities::has($this->caps, Capabilities::ARBITRARY_CALL)
                && !Capabilities::isSafeFunction($name)) {
                // Named by the template: route through the runtime deny-list
                // so a compiler bug alone cannot reach a blocked function.
                return sprintf(
                    '\\TplGuard\\Runtime\\Calls::fn(%s, [%s])',
                    var_export($name, true),
                    implode(', ', $args)
                );
            }
            if (!Capabilities::has($this->caps, Capabilities::ARBITRARY_CALL)
                && !(Capabilities::has($this->caps, Capabilities::SAFE_CALLS) && Capabilities::isSafeFunction($name))) {
                throw new \LogicException("Function $name reached the compiler without capability");
            }
            return sprintf('\\%s(%s)', $name, implode(', ', $args));
        }
        if ($e instanceof Ast\DynamicCall) {
            if (!Capabilities::has($this->caps, Capabilities::ARBITRARY_CALL)) {
                throw new \LogicException('Dynamic call reached the compiler without capability');
            }
            $args = array_map(fn (Ast\Expr $a) => $this->expr($a), $e->args);
            return sprintf('\\TplGuard\\Runtime\\Calls::call(%s, [%s])', $this->expr($e->callee), implode(', ', $args));
        }
        if ($e instanceof Ast\FilterExpr) {
            if (!Capabilities::has($this->caps, Capabilities::ARBITRARY_CALL) && !Capabilities::isSafeFilter($e->name)) {
                throw new \LogicException('Modifier reached the compiler without capability');
            }
            $args = array_map(fn (Ast\Expr $a) => $this->expr($a), $e->args);
            return sprintf(
                '\\TplGuard\\Runtime\\Modifiers::apply(%s, %s, [%s])',
                var_export($e->name, true),
                $this->expr($e->base),
                implode(', ', $args)
            );
        }
        if ($e instanceof Ast\Binary) {
            $l = $this->expr($e->left);
            $r = $this->expr($e->right);
            return match ($e->op) {
                '.' => sprintf('\\TplGuard\\Runtime\\Renderer::concat(%s, %s)', $l, $r),
                'and' => sprintf('((%s) && (%s))', $l, $r),
                'or' => sprintf('((%s) || (%s))', $l, $r),
                'xor' => sprintf('((%s) xor (%s))', $l, $r),
                'mod' => sprintf('((%s) %% (%s))', $l, $r),
                '==' => sprintf('((%s) == (%s))', $l, $r),
                '!=' => sprintf('((%s) != (%s))', $l, $r),
                '<>' => sprintf('((%s) <> (%s))', $l, $r),
                '<' => sprintf('((%s) < (%s))', $l, $r),
                '<=' => sprintf('((%s) <= (%s))', $l, $r),
                '>' => sprintf('((%s) > (%s))', $l, $r),
                '>=' => sprintf('((%s) >= (%s))', $l, $r),
                '+' => sprintf('((%s) + (%s))', $l, $r),
                '-' => sprintf('((%s) - (%s))', $l, $r),
                '*' => sprintf('((%s) * (%s))', $l, $r),
                '/' => sprintf('((%s) / (%s))', $l, $r),
                '%' => sprintf('((%s) %% (%s))', $l, $r),
                '&&' => sprintf('((%s) && (%s))', $l, $r),
                '||' => sprintf('((%s) || (%s))', $l, $r),
                '===' => sprintf('((%s) === (%s))', $l, $r),
                '!==' => sprintf('((%s) !== (%s))', $l, $r),
                default => sprintf('\\TplGuard\\Runtime\\Renderer::binop(%s, %s, %s)', var_export($e->op, true), $l, $r),
            };
        }
        if ($e instanceof Ast\Unary) {
            return match ($e->op) {
                '!' => '(!(' . $this->expr($e->operand) . '))',
                '-' => '(-(' . $this->expr($e->operand) . '))',
                '+' => '(+(' . $this->expr($e->operand) . '))',
                default => throw new \LogicException('Unknown unary op: ' . $e->op),
            };
        }
        if ($e instanceof Ast\Ternary) {
            $c = $this->expr($e->cond);
            $else = $this->expr($e->else);
            if ($e->then === null) {
                return sprintf('((%s) ?: (%s))', $c, $else);
            }
            return sprintf('((%s) ? (%s) : (%s))', $c, $this->expr($e->then), $else);
        }
        if ($e instanceof Ast\Coalesce) {
            return sprintf('((%s) ?? (%s))', $this->expr($e->left), $this->expr($e->right));
        }
        if ($e instanceof Ast\ArrayLit) {
            $parts = [];
            foreach ($e->items as [$k, $v]) {
                if ($k === null) {
                    $parts[] = $this->expr($v);
                } else {
                    $parts[] = $this->expr($k) . ' => ' . $this->expr($v);
                }
            }
            return '[' . implode(', ', $parts) . ']';
        }
        if ($e instanceof Ast\ConstRef) {
            return $this->constExpr($e->name);
        }
        if ($e instanceof Ast\StaticRef) {
            if (!Capabilities::has($this->caps, Capabilities::STATIC_ACCESS)) {
                throw new \LogicException('Static access reached the compiler without capability');
            }
            // Trusted templates only; class name is still validated.
            if (!preg_match('/^\\\\?[A-Za-z_][A-Za-z0-9_]*(\\\\[A-Za-z_][A-Za-z0-9_]*)*$/', $e->class)) {
                throw new \LogicException('Invalid class name in static access');
            }
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $e->member)) {
                throw new \LogicException('Invalid member name in static access');
            }
            return $e->isProp
                ? sprintf('\\%s::$%s', ltrim($e->class, '\\'), $e->member)
                : sprintf('\\%s::%s', ltrim($e->class, '\\'), $e->member);
        }
        if ($e instanceof Ast\NewExpr) {
            if (!Capabilities::has($this->caps, Capabilities::STATIC_ACCESS)) {
                throw new \LogicException('Object instantiation reached the compiler without capability');
            }
            if (!preg_match('/^\\\\?[A-Za-z_][A-Za-z0-9_]*(\\\\[A-Za-z_][A-Za-z0-9_]*)*$/', $e->class)) {
                throw new \LogicException('Invalid class name');
            }
            $args = array_map(fn (Ast\Expr $a) => $this->expr($a), $e->args);
            return sprintf('new \\%s(%s)', ltrim($e->class, '\\'), implode(', ', $args));
        }
        throw new \LogicException('Unknown expression: ' . get_class($e));
    }

    private function constExpr(string $name): string
    {
        $consts = [
            'PHP_EOL' => PHP_EOL, 'E_ALL' => E_ALL, 'E_NOTICE' => E_NOTICE,
            'E_WARNING' => E_WARNING, 'M_PI' => M_PI, 'PHP_INT_MAX' => PHP_INT_MAX,
            'SORT_ASC' => SORT_ASC, 'SORT_DESC' => SORT_DESC, 'SORT_NUMERIC' => SORT_NUMERIC,
            'SORT_STRING' => SORT_STRING, 'ENT_QUOTES' => ENT_QUOTES, 'ENT_COMPAT' => ENT_COMPAT,
        ];
        if (array_key_exists($name, $consts)) {
            return var_export($consts[$name], true);
        }
        throw new \LogicException("Unknown constant in template: $name");
    }

    private function line(string $s): void
    {
        $this->lines[] = str_repeat('    ', $this->indent) . $s;
    }

    /**
     * True when a PHP fragment ends while still in inline-HTML mode (its last
     * close tag was not followed by another open tag).  A cheap state walk
     * that ignores tags inside strings and comments.
     */
    private static function endsInHtmlMode(string $code): bool
    {
        $inPhp = true;
        $len = strlen($code);
        for ($i = 0; $i < $len; $i++) {
            $c = $code[$i];
            if ($c === '\'' || $c === '"') {
                // Skip a single/double quoted string.
                $q = $c;
                for ($i++; $i < $len; $i++) {
                    if ($code[$i] === '\\') {
                        $i++;
                        continue;
                    }
                    if ($code[$i] === $q) {
                        break;
                    }
                }
                continue;
            }
            if ($c === '#' || ($c === '/' && ($code[$i + 1] ?? '') === '/')) {
                while ($i < $len && $code[$i] !== "\n") {
                    $i++;
                }
                continue;
            }
            if ($c === '/' && ($code[$i + 1] ?? '') === '*') {
                $i += 2;
                while ($i < $len && !($code[$i] === '*' && ($code[$i + 1] ?? '') === '/')) {
                    $i++;
                }
                $i++;
                continue;
            }
            if ($c === '?' && ($code[$i + 1] ?? '') === '>') {
                if ($inPhp) {
                    $inPhp = false;
                    $i++;
                }
                continue;
            }
            if ($c === '<' && ($code[$i + 1] ?? '') === '?' && ($code[$i + 2] ?? '') === 'p') {
                $inPhp = true;
            }
        }
        return !$inPhp;
    }
}
