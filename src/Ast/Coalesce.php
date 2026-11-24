<?php
declare(strict_types=1);

namespace TplGuard\Ast;

final class Coalesce extends Expr
{
    public function __construct(public Expr $left, public Expr $right) {}
}
