<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{assign var=name value=expr}` */
final class AssignNode extends Node
{
    public function __construct(public string $name, public Expr $value) {}
}
