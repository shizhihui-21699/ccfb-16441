<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** A plugin/custom tag: `{tag:rank uid=$user.id} ... {/tag:rank}` */
final class TagNode extends Node
{
    /**
     * @param array<string, Expr> $attrs
     * @param list<Node> $body
     */
    public function __construct(
        public string $name,
        public array $attrs,
        public array $body = [],
        public bool $selfClosing = true,
    ) {}
}
