<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{$expr}` (or `{expr}`): evaluate and print. */
final class Output extends Node
{
    public function __construct(public Expr $expr, public bool $raw = false) {}
}
