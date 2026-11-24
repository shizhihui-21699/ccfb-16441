<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{php} ... {/php}` — raw PHP, trusted templates only. */
final class PhpNode extends Node
{
    public function __construct(public string $code) {}
}
