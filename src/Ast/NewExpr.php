<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `new Foo(...)` — banned outside the trusted tier. */
final class NewExpr extends Expr
{
    /** @param list<Expr> $args */
    public function __construct(public string $class, public array $args) {}
}
