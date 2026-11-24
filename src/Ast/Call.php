<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `count($x)` — a call to a statically named function. */
final class Call extends Expr
{
    /** @param list<Expr> $args */
    public function __construct(public string $name, public array $args) {}
}
