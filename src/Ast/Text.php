<?php
declare(strict_types=1);

namespace TplGuard\Ast;

final class Text extends Node
{
    public function __construct(public string $text) {}
}
