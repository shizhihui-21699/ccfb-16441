<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{literal} ... {/literal}` */
final class LiteralNode extends Node
{
    public function __construct(public string $text) {}
}
