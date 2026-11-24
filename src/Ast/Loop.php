<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{loop $list $k $v}`, `{foreach $list as $k => $v}`, `{foreach from=$list item=v}` */
final class Loop extends Node
{
    /** @param list<Node> $body */
    public function __construct(
        public Expr $subject,
        public ?string $keyVar,
        public string $valVar,
        public array $body,
    ) {}
}
