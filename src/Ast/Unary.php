<?php
declare(strict_types=1);

namespace TplGuard\Ast;

final class Unary extends Expr
{
    public function __construct(public string $op, public Expr $operand) {}
}
