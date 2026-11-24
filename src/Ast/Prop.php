<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `$obj->prop` — property read. */
final class Prop extends Expr
{
    public function __construct(public Expr $base, public string $name) {}
}
