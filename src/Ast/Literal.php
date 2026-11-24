<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** String / int / float / bool / null literal. */
final class Literal extends Expr
{
    public function __construct(public mixed $value) {}
}
