<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `$a[$expr]` on a non-path base. */
final class Index extends Expr
{
    public function __construct(public Expr $base, public Expr $key) {}
}
