<?php
declare(strict_types=1);

namespace TplGuard\Parser;

use TplGuard\Ast;

/**
 * Recursive-descent / precedence-climbing expression parser.
 *
 * The grammar is a deliberately small, closed set.  It is *not* PHP: there is
 * no way for the parser to emit a call to an arbitrary function with an
 * arbitrary name, no `eval`, no backtick, no `include`, no `?>`; every node it
 * produces is visited by Security\Analyzer before compilation.
 */
final class ExpressionParser
{
    /** @var list<Token> */
    private array $tokens;
    private int $i = 0;

    /** Binary operator => [leftBindingPower, rightAssoc] */
    private const BINARY = [
        'or'   => [10, false],
        'xor'  => [11, false],
        'and'  => [12, false],
        '||'   => [20, false],
        '&&'   => [25, false],
        '=='   => [40, false],
        '!='   => [40, false],
        '<>'   => [40, false],
        '==='  => [40, false],
        '!=='  => [40, false],
        '<=>'  => [40, false],
        '<'    => [45, false],
        '<='   => [45, false],
        '>'    => [45, false],
        '>='   => [45, false],
        '&'    => [48, false], // bitwise-and ('|' is the modifier separator)
        '+'    => [50, false],
        '-'    => [50, false],
        '.'    => [50, false],
        '*'    => [60, false],
        '/'    => [60, false],
        '%'    => [60, false],
        'mod'  => [60, false],
    ];

    private const COALESCE = [30, true];

    public function __construct(string $source, private ParserOptions $opts)
    {
        $this->tokens = Lexer::tokenize($source);
    }

    public static function parse(string $source, ParserOptions $opts): Ast\Expr
    {
        $p = new self($source, $opts);
        $expr = $p->parseExpression(0);
        $tok = $p->peek();
        if (!$tok->is(Token::EOF)) {
            throw new ParseException(sprintf('Unexpected "%s" in expression', $tok->value), $tok->pos);
        }
        return $expr;
    }

    private function peek(int $o = 0): Token
    {
        return $this->tokens[min($this->i + $o, count($this->tokens) - 1)];
    }

    private function next(): Token
    {
        return $this->tokens[$this->i++];
    }

    private function expect(string $type, ?string $value = null): Token
    {
        $t = $this->peek();
        if (!$t->is($type, $value)) {
            throw new ParseException(
                sprintf('Expected %s%s, got "%s"', $type, $value !== null ? " \"$value\"" : '', $t->value),
                $t->pos
            );
        }
        return $this->next();
    }

    /**
     * `{$x|escape}`, `{$x|escape:'html'}`, `{$x|substr:0,10}`, chains.
     * A `||` token is logical-or, not two pipes, so the lexer's two-char
     * operator already disambiguates it.
     */
    private function parseModifierChain(Ast\Expr $node): Ast\Expr
    {
        while ($this->peek()->is(Token::OP, '|')) {
            $this->next();
            $nameTok = $this->next();
            if ($nameTok->type !== Token::IDENT) {
                throw new ParseException('Expected modifier name after "|"', $nameTok->pos);
            }
            $args = [];
            // Arguments are `:arg` or `:arg,arg`; stop at anything that
            // starts a new binary operation or closes the tag.
            while ($this->peek()->is(Token::OP, ':')) {
                $this->next();
                $args[] = $this->parseExpression(0);
                if ($this->peek()->is(Token::PUNC, ',')) {
                    $this->next();
                    continue;
                }
                break;
            }
            $f = new Ast\FilterExpr($node, $nameTok->value, $args);
            $f->line = $node->line;
            $node = $f;
        }
        return $node;
    }

    /** @param int $minBp minimum binding power */
    private function parseExpression(int $minBp): Ast\Expr
    {
        $left = $this->parseUnary();

        // Modifiers bind tighter than every binary operator: `$a|escape == 'x'`
        // means `($a|escape) == 'x'`.  Legacy engines also allow chaining.
        $left = $this->parseModifierChain($left);

        while (true) {
            $t = $this->peek();

            // Ternary
            if ($t->is(Token::OP, '?') && 5 >= $minBp) {
                $this->next();
                if ($this->peek()->is(Token::OP, ':')) {
                    $this->next();
                    $else = $this->parseExpression(5);
                    $node = new Ast\Ternary($left, null, $else);
                } else {
                    $then = $this->parseExpression(0);
                    $this->expect(Token::OP, ':');
                    $else = $this->parseExpression(5);
                    $node = new Ast\Ternary($left, $then, $else);
                }
                $node->line = $left->line;
                $left = $node;
                continue;
            }

            // Null coalescing (right associative)
            if ($t->is(Token::OP, '??')) {
                [$bp, $rightAssoc] = self::COALESCE;
                if ($bp < $minBp) {
                    break;
                }
                $this->next();
                $right = $this->parseExpression($rightAssoc ? $bp : $bp + 1);
                $node = new Ast\Coalesce($left, $right);
                $node->line = $left->line;
                $left = $node;
                continue;
            }

            $opName = null;
            $bp = 0;
            $rightAssoc = false;
            if ($t->type === Token::OP && isset(self::BINARY[$t->value])) {
                $opName = $t->value;
                [$bp, $rightAssoc] = self::BINARY[$opName];
            } elseif ($t->type === Token::IDENT && isset(self::BINARY[$t->value])) {
                $opName = $t->value;
                [$bp, $rightAssoc] = self::BINARY[$opName];
            }
            if ($opName === null || $bp < $minBp) {
                break;
            }
            $this->next();
            $right = $this->parseExpression($rightAssoc ? $bp : $bp + 1);
            $node = new Ast\Binary($opName, $left, $right);
            $node->line = $left->line;
            $left = $node;
        }
        return $left;
    }

    private function parseUnary(): Ast\Expr
    {
        $t = $this->peek();
        if ($t->is(Token::OP, '!') || $t->is(Token::OP, '-') || $t->is(Token::OP, '+')
            || $t->is(Token::IDENT, 'not')) {
            $this->next();
            $operand = $this->parseUnary();
            // Fold constant negation.
            if ($t->value === '-' && $operand instanceof Ast\Literal && is_int($operand->value)) {
                return new Ast\Literal(-$operand->value);
            }
            $node = new Ast\Unary($t->value === 'not' ? '!' : $t->value, $operand);
            $node->line = $operand->line;
            return $node;
        }
        if ($t->is(Token::OP, '@')) {
            throw new ParseException('Error-suppression operator is not allowed in templates', $t->pos);
        }
        return $this->parsePostfix($this->parsePrimary());
    }

    private function parsePrimary(): Ast\Expr
    {
        $t = $this->next();
        switch (true) {
            case $t->is(Token::NUM):
                $node = new Ast\Literal(
                    (str_contains($t->value, '.') || stripos($t->value, 'e') !== false)
                        ? (float) $t->value
                        : (int) $t->value
                );
                break;
            case $t->is(Token::STR):
                $node = new Ast\Literal(self::decodeSingle((string) $t->value));
                break;
            case $t->type === 'dstr':
                $node = new Ast\Literal(self::decodeDouble((string) $t->value));
                break;
            case $t->is(Token::VAR):
                $node = new Ast\VarRef($t->value);
                break;
            case $t->is(Token::PUNC, '('):
                $node = $this->parseExpression(0);
                $this->expect(Token::PUNC, ')');
                break;
            case $t->is(Token::PUNC, '['):
                $node = $this->parseArrayLiteral();
                break;
            case $t->is(Token::IDENT):
                $node = $this->parseIdentPrimary($t);
                break;
            default:
                throw new ParseException(sprintf('Unexpected "%s"', $t->value), $t->pos);
        }
        $node->line = $t->pos;
        return $node;
    }

    private function parseIdentPrimary(Token $t): Ast\Expr
    {
        $lower = strtolower($t->value);
        if ($lower === 'true') {
            return new Ast\Literal(true);
        }
        if ($lower === 'false') {
            return new Ast\Literal(false);
        }
        if ($lower === 'null') {
            return new Ast\Literal(null);
        }
        // Function call:  name ( ... )
        if ($this->peek()->is(Token::PUNC, '(')) {
            $this->next();
            return new Ast\Call($t->value, $this->parseArgList(')'));
        }
        // Class constant / static member:  Foo::BAR
        if ($this->peek()->is(Token::OP, ':') && $this->peek(1)->is(Token::OP, ':')) {
            $this->next();
            $this->next();
            $member = $this->peek();
            if ($member->is(Token::IDENT)) {
                $this->next();
                return new Ast\StaticRef($t->value, $member->value, false);
            }
            if ($member->is(Token::VAR)) {
                $this->next();
                return new Ast\StaticRef($t->value, $member->value, true);
            }
            throw new ParseException('Expected class member after "::"', $member->pos);
        }
        return new Ast\ConstRef($t->value);
    }

    private function parseArrayLiteral(): Ast\Expr
    {
        $items = [];
        while (!$this->peek()->is(Token::PUNC, ']')) {
            $first = $this->parseExpression(0);
            if ($this->peek()->is(Token::OP, '=>')) {
                $this->next();
                $value = $this->parseExpression(0);
                $items[] = [$first, $value];
            } else {
                $items[] = [null, $first];
            }
            if ($this->peek()->is(Token::PUNC, ',')) {
                $this->next();
            } else {
                break;
            }
        }
        $this->expect(Token::PUNC, ']');
        return new Ast\ArrayLit($items);
    }

    /** @return list<Ast\Expr> */
    private function parseArgList(string $closer): array
    {
        $args = [];
        while (!$this->peek()->is(Token::PUNC, $closer)) {
            $args[] = $this->parseExpression(0);
            if ($this->peek()->is(Token::PUNC, ',')) {
                $this->next();
            } else {
                break;
            }
        }
        $this->expect(Token::PUNC, $closer);
        return $args;
    }

    private function parsePostfix(Ast\Expr $node): Ast\Expr
    {
        while (true) {
            $t = $this->peek();

            // Dynamic index  a[...]
            if ($t->is(Token::PUNC, '[')) {
                $this->next();
                $key = $this->parseExpression(0);
                $this->expect(Token::PUNC, ']');
                $node = $this->foldIndex($node, $key);
                continue;
            }

            // Property / method access  a->b  a->b(...)
            if ($t->is(Token::OP, '-') && $this->peek(1)->is(Token::OP, '>')) {
                $this->next();
                $this->next();
                $nameTok = $this->next();
                if ($nameTok->type === Token::VAR) {
                    // $obj->$name — dynamic property: keep as Prop with a
                    // marker so the analyzer can reject it.
                    $node = new Ast\Prop($node, '$' . $nameTok->value);
                    continue;
                }
                if (!$nameTok->is(Token::IDENT)) {
                    throw new ParseException('Expected property name after "->"', $nameTok->pos);
                }
                if ($this->peek()->is(Token::PUNC, '(')) {
                    $this->next();
                    $args = $this->parseArgList(')');
                    $node = new Ast\MethodCall($node, $nameTok->value, $args);
                } else {
                    $node = new Ast\Prop($node, $nameTok->value);
                }
                continue;
            }

            // Dot key access  a.b  (legacy Discuz syntax)
            if ($this->isDotKeyAccess($t)) {
                $this->next(); // '.'
                $keyTok = $this->next();
                $key = $keyTok->type === Token::NUM ? (int) $keyTok->value : $keyTok->value;
                $node = $this->foldIndex($node, new Ast\Literal($key));
                continue;
            }

            // Dynamic call  expr(...)
            if ($t->is(Token::PUNC, '(')) {
                $this->next();
                $args = $this->parseArgList(')');
                $node = new Ast\DynamicCall($node, $args);
                continue;
            }

            break;
        }
        return $node;
    }

    private function isDotKeyAccess(Token $t): bool
    {
        if (!$t->is(Token::OP, '.')) {
            return false;
        }
        if (!$this->peek(1)->is(Token::IDENT) && !$this->peek(1)->is(Token::NUM)) {
            return false;
        }
        return match ($this->opts->dotSyntax) {
            'key'    => true,
            'concat' => false,
            default  => !$t->spaceBefore && !$this->peek(1)->spaceBefore,
        };
    }

    private function foldIndex(Ast\Expr $base, Ast\Expr $key): Ast\Expr
    {
        if ($base instanceof Ast\VarRef && $key instanceof Ast\Literal) {
            $base->path[] = ['key', $key->value];
            return $base;
        }
        if ($base instanceof Ast\VarRef && $key instanceof Ast\ConstRef) {
            // {$a[b]} — Discuz allows unquoted keys.
            $base->path[] = ['key', $key->name];
            return $base;
        }
        if ($base instanceof Ast\VarRef) {
            $base->path[] = ['expr', $key];
            return $base;
        }
        $node = new Ast\Index($base, $key);
        $node->line = $base->line;
        return $node;
    }

    private static function decodeSingle(string $s): string
    {
        return strtr($s, ['\\\\' => '\\', "\\'" => "'"]);
    }

    private static function decodeDouble(string $s): string
    {
        return strtr($s, [
            '\\\\' => '\\',
            '\\"'  => '"',
            '\\n'  => "\n",
            '\\r'  => "\r",
            '\\t'  => "\t",
            '\\$'  => '$',
        ]);
    }
}
