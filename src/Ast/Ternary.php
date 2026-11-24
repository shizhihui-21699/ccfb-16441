<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `$a ? $b : $c`, `$a ?: $c` ($then === null). */
final class Ternary extends Expr
{
    public function __construct(public Expr $cond, public ?Expr $then, public Expr $else) {}
}
