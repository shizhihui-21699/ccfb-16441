<?php
declare(strict_types=1);

namespace TplGuard\Ast;

final class ArrayLit extends Expr
{
    /** @param list<array{0:?Expr,1:Expr}> $items */
    public function __construct(public array $items) {}
}
