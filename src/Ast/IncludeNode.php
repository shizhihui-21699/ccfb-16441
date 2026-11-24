<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{include file="..." key=expr}` / `{template name}` */
final class IncludeNode extends Node
{
    /** @param array<string, Expr> $params */
    public function __construct(
        public Expr $file,
        public array $params,
        public bool $dynamic,
        public ?string $staticName,
    ) {}
}
