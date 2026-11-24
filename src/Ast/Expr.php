<?php
declare(strict_types=1);

namespace TplGuard\Ast;

/**
 * Expression AST.
 *
 * The parser never produces a node for arbitrary PHP code: every construct a
 * template can write maps onto one of the node types in this namespace.
 * Anything that cannot be expressed as one of them is a parse error.  This is
 * what makes the static analysis in Security\Analyzer meaningful: the AST is
 * the complete set of things a template is able to ask the engine to do.
 */
abstract class Expr
{
    public int $line = 0;
}
