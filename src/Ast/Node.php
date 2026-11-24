<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/** Template statement AST. Plain text, output, control flow and includes. */
abstract class Node
{
    public int $line = 0;
}
