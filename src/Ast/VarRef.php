<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/**
 * Variable read: `{$user.name}`, `{$a['b']}` folded into a static path.
 *
 * $path is a list of [kind, value] where kind is 'key' (string|int) or
 * 'expr' (dynamic segment such as `.$k`).
 */
final class VarRef extends Expr
{
    /** @param list<array{0:string,1:mixed}> $path */
    public function __construct(public string $root, public array $path = []) {}
}
