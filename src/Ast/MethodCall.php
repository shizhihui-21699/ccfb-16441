<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `$obj->method(...)` — method call. Blocked outside elevated tiers. */
final class MethodCall extends Expr
{
    /** @param list<Expr> $args */
    public function __construct(public Expr $base, public string $name, public array $args) {}
}
