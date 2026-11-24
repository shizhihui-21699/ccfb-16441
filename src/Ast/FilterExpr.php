<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{$x|escape:'html'}` — modifier / filter chain. */
final class FilterExpr extends Expr
{
    /** @param list<Expr> $args */
    public function __construct(public Expr $base, public string $name, public array $args) {}
}
