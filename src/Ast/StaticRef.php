<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `Foo::BAR` / `Foo::$x` — class constant / static property access. */
final class StaticRef extends Expr
{
    public function __construct(public string $class, public string $member, public bool $isProp) {}
}
