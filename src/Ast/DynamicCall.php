<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `$f(1,2)` — callee is an expression: banned outside trusted tier. */
final class DynamicCall extends Expr
{
    /** @param list<Expr> $args */
    public function __construct(public Expr $callee, public array $args) {}
}
