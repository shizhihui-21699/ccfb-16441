<?php
declare(strict_types=1);

namespace TplGuard\Security;

use TplGuard\Ast;

/**
 * Static capability analysis over the template AST.
 *
 * Runs once per template *compile* (not per request) and decides whether the
 * template may be compiled at the capability level it claims.  Rejection is a
 * compile-time error: a hostile template is never turned into code at all,
 * so the hot path pays nothing for it.
 */
final class Analyzer
{
    /** @var list<Finding> */
    private array $findings = [];
    private bool $usedPhp = false;
    private bool $usedDynamicCall = false;

    /** @param list<string> $caps */
    public function __construct(private array $caps) {}

    /** @param list<Ast\Node> $nodes */
    public function analyze(array $nodes): AnalysisResult
    {
        $this->findings = [];
        $this->usedPhp = false;
        $this->usedDynamicCall = false;
        $this->walkNodes($nodes);
        return new AnalysisResult($this->findings, $this->usedPhp, $this->usedDynamicCall);
    }

    /** @param list<Ast\Node> $nodes */
    private function walkNodes(array $nodes): void
    {
        foreach ($nodes as $n) {
            $this->walkNode($n);
        }
    }

    private function walkNode(Ast\Node $n): void
    {
        if ($n instanceof Ast\Text || $n instanceof Ast\LiteralNode) {
            return;
        }
        if ($n instanceof Ast\Output) {
            $this->walkExpr($n->expr);
            return;
        }
        if ($n instanceof Ast\IfNode) {
            foreach ($n->branches as [$cond, $body]) {
                $this->walkExpr($cond);
                $this->walkNodes($body);
            }
            $this->walkNodes($n->else);
            return;
        }
        if ($n instanceof Ast\Loop) {
            $this->walkExpr($n->subject);
            $this->walkNodes($n->body);
            return;
        }
        if ($n instanceof Ast\AssignNode) {
            $this->walkExpr($n->value);
            return;
        }
        if ($n instanceof Ast\IncludeNode) {
            if (!Capabilities::has($this->caps, Capabilities::DYNAMIC_INCLUDE)) {
                if ($n->dynamic || !$this->isStaticSafeInclude($n->file)) {
                    $this->error('include.dynamic', 'Dynamic template include is not permitted', $n->line);
                }
            }
            $this->walkExpr($n->file);
            foreach ($n->params as $expr) {
                $this->walkExpr($expr);
            }
            return;
        }
        if ($n instanceof Ast\PhpNode) {
            $this->usedPhp = true;
            if (!Capabilities::has($this->caps, Capabilities::PHP)) {
                $this->error('php.block', 'Raw PHP blocks are not permitted in this template', $n->line, $this->shortCode($n->code));
            }
            return;
        }
        if ($n instanceof Ast\EvalNode) {
            $this->usedPhp = true;
            if (!Capabilities::has($this->caps, Capabilities::PHP)) {
                $this->error('php.eval', 'eval expression is not permitted in this template', $n->line, $this->shortCode($n->code));
            }
            return;
        }
        if ($n instanceof Ast\TagNode) {
            if (!Capabilities::has($this->caps, Capabilities::PLUGIN_TAGS)) {
                $this->error('tag.plugin', sprintf('Plugin tag {%s} is not permitted', $n->name), $n->line);
            }
            foreach ($n->attrs as $expr) {
                $this->walkExpr($expr);
            }
            $this->walkNodes($n->body);
            return;
        }
    }

    private function walkExpr(Ast\Expr $e): void
    {
        if ($e instanceof Ast\Literal) {
            return;
        }
        if ($e instanceof Ast\VarRef) {
            if (self::isSuperglobal($e->root)) {
                $this->error('expr.superglobal', sprintf('Reading %s is not permitted in any template', '$' . $e->root), $e->line);
            }
            foreach ($e->path as [$kind, $payload]) {
                if ($kind === 'expr') {
                    $this->requireCap(Capabilities::DYNAMIC_INDEX, 'expr.dynamic_index', 'Dynamic key access is not permitted', $e->line);
                    $this->walkExpr($payload);
                }
            }
            return;
        }
        if ($e instanceof Ast\Index) {
            $this->requireCap(Capabilities::DYNAMIC_INDEX, 'expr.dynamic_index', 'Dynamic key access is not permitted', $e->line);
            $this->walkExpr($e->base);
            $this->walkExpr($e->key);
            return;
        }
        if ($e instanceof Ast\Prop) {
            if (!Capabilities::has($this->caps, Capabilities::PROPERTY_ACCESS)) {
                $this->error('expr.property', sprintf('Property read ->%s is not permitted', $e->name), $e->line);
            }
            if (str_starts_with($e->name, '$')) {
                $this->error('expr.dynamic_property', 'Dynamic property name is not permitted', $e->line);
            }
            $this->walkExpr($e->base);
            return;
        }
        if ($e instanceof Ast\MethodCall) {
            $this->requireCap(Capabilities::METHOD_CALL, 'expr.method', sprintf('Method call ->%s() is not permitted', $e->name), $e->line);
            if (str_starts_with($e->name, '_')) {
                $this->error('expr.magic_method', sprintf('Call to magic method ->%s() is not permitted', $e->name), $e->line);
            }
            $this->walkExpr($e->base);
            foreach ($e->args as $a) {
                $this->walkExpr($a);
            }
            return;
        }
        if ($e instanceof Ast\Call) {
            $name = $e->name;
            if (Capabilities::isDeniedFunction($name)) {
                $this->error('call.denied', sprintf('Function %s() is never permitted in templates', $name), $e->line);
            } elseif (!Capabilities::has($this->caps, Capabilities::ARBITRARY_CALL)) {
                if (!Capabilities::has($this->caps, Capabilities::SAFE_CALLS) || !Capabilities::isSafeFunction($name)) {
                    $this->error('call.function', sprintf('Function %s() is not permitted in this template', $name), $e->line);
                }
            }
            foreach ($e->args as $a) {
                $this->walkExpr($a);
            }
            return;
        }
        if ($e instanceof Ast\DynamicCall) {
            $this->usedDynamicCall = true;
            $this->requireCap(Capabilities::ARBITRARY_CALL, 'expr.dynamic_call', 'Calling a computed callable is not permitted', $e->line);
            $this->walkExpr($e->callee);
            foreach ($e->args as $a) {
                $this->walkExpr($a);
            }
            return;
        }
        if ($e instanceof Ast\FilterExpr) {
            $name = $e->name;
            if (strtolower($name) === 'eval' || strtolower($name) === 'php') {
                $this->usedPhp = true;
                $this->requireCap(Capabilities::EVAL_MODIFIER, 'filter.eval', 'The eval modifier is not permitted', $e->line);
            } elseif (!Capabilities::has($this->caps, Capabilities::ARBITRARY_CALL) && !Capabilities::isSafeFilter($name)) {
                $this->error('filter.unknown', sprintf('Modifier |%s is not permitted in this template', $name), $e->line);
            }
            $this->walkExpr($e->base);
            foreach ($e->args as $a) {
                $this->walkExpr($a);
            }
            return;
        }
        if ($e instanceof Ast\Binary) {
            $this->walkExpr($e->left);
            $this->walkExpr($e->right);
            return;
        }
        if ($e instanceof Ast\Unary) {
            $this->walkExpr($e->operand);
            return;
        }
        if ($e instanceof Ast\Ternary) {
            $this->walkExpr($e->cond);
            if ($e->then) {
                $this->walkExpr($e->then);
            }
            $this->walkExpr($e->else);
            return;
        }
        if ($e instanceof Ast\Coalesce) {
            $this->walkExpr($e->left);
            $this->walkExpr($e->right);
            return;
        }
        if ($e instanceof Ast\ArrayLit) {
            foreach ($e->items as [$k, $v]) {
                if ($k) {
                    $this->walkExpr($k);
                }
                $this->walkExpr($v);
            }
            return;
        }
        if ($e instanceof Ast\StaticRef) {
            $this->requireCap(Capabilities::STATIC_ACCESS, 'expr.static', 'Static class access is not permitted', $e->line);
            return;
        }
        if ($e instanceof Ast\NewExpr) {
            $this->requireCap(Capabilities::STATIC_ACCESS, 'expr.new', 'Object instantiation is not permitted', $e->line);
            foreach ($e->args as $a) {
                $this->walkExpr($a);
            }
            return;
        }
        if ($e instanceof Ast\ConstRef) {
            // Constants are baked into the compiled output as literals; the
            // compiler consults a fixed whitelist.
            return;
        }
    }

    private static function isSuperglobal(string $root): bool
    {
        return in_array($root, [
            '_SERVER', '_ENV', '_GET', '_POST', '_COOKIE', '_FILES', '_REQUEST',
            '_SESSION', 'GLOBALS',
        ], true);
    }

    private function isStaticSafeInclude(Ast\Expr $e): bool    {
        return $e instanceof Ast\Literal && is_string($e->value)
            && preg_match('#^[A-Za-z0-9_/.-]+$#', $e->value) === 1
            && !str_contains($e->value, '..');
    }

    private function requireCap(string $cap, string $rule, string $msg, int $line): void
    {
        if (!Capabilities::has($this->caps, $cap)) {
            $this->error($rule, $msg, $line);
        }
    }

    private function error(string $rule, string $msg, int $line, string $snippet = ''): void
    {
        $this->findings[] = new Finding(Finding::ERROR, $rule, $msg, $line, $snippet);
    }

    private function shortCode(string $code): string
    {
        $code = trim(preg_replace('/\s+/', ' ', $code) ?? '');
        return function_exists('mb_substr') ? mb_substr($code, 0, 120) : substr($code, 0, 120);
    }
}
