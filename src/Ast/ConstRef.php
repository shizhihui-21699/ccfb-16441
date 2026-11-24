<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** Bare identifier used as a constant: `PHP_EOL`, `E_ALL`, ... */
final class ConstRef extends Expr
{
    public function __construct(public string $name) {}
}
