<?php
declare(strict_types=1);

namespace TplGuard\Ast;

final class Binary extends Expr
{
    public function __construct(public string $op, public Expr $left, public Expr $right) {}
}
