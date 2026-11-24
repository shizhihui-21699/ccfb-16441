<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** `{if expr} ... {elseif expr} ... {else} ... {/if}`; also `{switch}`. */
final class IfNode extends Node
{
    /**
     * @param list<array{0:Expr,1:list<Node>}> $branches
     * @param list<Node> $else
     */
    public function __construct(public array $branches, public array $else = []) {}

    /** For `{switch}`: the subject every `{case}` compares against. */
    public ?Expr $switchSubject = null;
}
