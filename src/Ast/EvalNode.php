<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{eval ...}` / `<!--{eval ...}-->` — raw PHP statement, trusted only. */
final class EvalNode extends Node
{
    public function __construct(public string $code) {}
}
