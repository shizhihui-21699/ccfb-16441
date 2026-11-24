<?php
declare(strict_types=1);

namespace TplGuard\Parser;

final class Token
{
    public const NUM = 'num';
    public const STR = 'str';
    public const IDENT = 'ident';
    public const VAR = 'var';
    public const OP = 'op';
    public const PUNC = 'punc';
    public const EOF = 'eof';

    public function __construct(
        public string $type,
        public string $value,
        public int $pos,
        public bool $spaceBefore = false,
    ) {}

    public function is(string $type, ?string $value = null): bool
    {
        return $this->type === $type && ($value === null || $this->value === $value);
    }
}

/**
 * Tokenizer for template expressions.
 *
 * Deliberately narrow: it knows integers, floats, single/double quoted
 * strings, identifiers, `$variables` and a fixed operator set.  There is no
 * token that can express PHP constructs like backticks, `?>` tags, heredocs,
 * variable-variables, or shell execution.
 */
final class Lexer
{
    /** @var list<Token> */
    private array $tokens = [];
    private int $i = 0;
    private int $n;

    private const OPERATORS = [
        '===', '!==', '<=>', '==', '!=', '<>', '<=', '>=', '&&', '||', '??', '**', '=>',
        '+', '-', '*', '/', '%', '.', '<', '>', '!', '=', '|', '?', ':',
        '(', ')', '[', ']', ',',
    ];

    public function __construct(private string $src)
    {
        $this->n = strlen($src);
    }

    /** @return list<Token> */
    public static function tokenize(string $src): array
    {
        return (new self($src))->run();
    }

    /**
     * Upper bound on tokens in a single expression.  A template can be edited
     * by a moderator, so an expression like `"A"."B"."C"...` repeated a
     * million times must fail fast instead of consuming the worker's memory
     * when it is parsed, stamped and compiled. Real templates are tiny.
     */
    private const MAX_TOKENS = 20000;

    /** @return list<Token> */
    private function run(): array
    {
        $space = false;
        while ($this->i < $this->n) {
            if (count($this->tokens) > self::MAX_TOKENS) {
                throw new ParseException('Expression is too long', $this->i);
            }
            $c = $this->src[$this->i];
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                $space = true;
                $this->i++;
                continue;
            }
            $start = $this->i;

            if ($c === '$') {
                $this->tokens[] = $this->readVariable($space, $start);
                $space = false;
                continue;
            }
            if (ctype_digit($c)) {
                $this->tokens[] = $this->readNumber($space, $start);
                $space = false;
                continue;
            }
            if ($c === '\'' || $c === '"') {
                $this->tokens[] = $this->readString($c, $space, $start);
                $space = false;
                continue;
            }
            if (ctype_alpha($c) || $c === '_') {
                $this->tokens[] = $this->readIdent($space, $start);
                $space = false;
                continue;
            }

            $matched = null;
            foreach (self::OPERATORS as $op) {
                if (substr($this->src, $this->i, strlen($op)) === $op) {
                    $matched = $op;
                    break;
                }
            }
            if ($matched === null) {
                throw new ParseException(sprintf('Unexpected character %s in expression', json_encode($c)), $start);
            }
            $type = in_array($matched, ['(', ')', '[', ']', ','], true) ? Token::PUNC : Token::OP;
            $this->tokens[] = new Token($type, $matched, $start, $space);
            $this->i += strlen($matched);
            $space = false;
        }
        $this->tokens[] = new Token(Token::EOF, '', $this->n, $space);
        return $this->tokens;
    }

    private function readVariable(bool $space, int $start): Token
    {
        $this->i++; // '$'
        $name = '';
        while ($this->i < $this->n && (ctype_alnum($this->src[$this->i]) || $this->src[$this->i] === '_')) {
            $name .= $this->src[$this->i++];
        }
        if ($name === '') {
            throw new ParseException('Expected variable name after "$"', $start);
        }
        return new Token(Token::VAR, $name, $start, $space);
    }

    private function readNumber(bool $space, int $start): Token
    {
        $num = '';
        if (substr($this->src, $this->i, 2) === '0x' || substr($this->src, $this->i, 2) === '0X') {
            $num = substr($this->src, $this->i, 2);
            $this->i += 2;
            while ($this->i < $this->n && ctype_xdigit($this->src[$this->i])) {
                $num .= $this->src[$this->i++];
            }
            return new Token(Token::NUM, (string) hexdec(substr($num, 2)), $start, $space);
        }
        while ($this->i < $this->n) {
            $c = $this->src[$this->i];
            if (ctype_digit($c)) {
                $num .= $c;
                $this->i++;
                continue;
            }
            // A '.' belongs to the number only when a digit follows it, so
            // that legacy `$list.0.title` keeps its dots.
            if ($c === '.' && !str_contains($num, '.')
                && $this->i + 1 < $this->n && ctype_digit($this->src[$this->i + 1])) {
                $num .= $c;
                $this->i++;
                continue;
            }
            break;
        }
        if ($this->i < $this->n && ($this->src[$this->i] === 'e' || $this->src[$this->i] === 'E')) {
            $num .= $this->src[$this->i++];
            if ($this->i < $this->n && ($this->src[$this->i] === '+' || $this->src[$this->i] === '-')) {
                $num .= $this->src[$this->i++];
            }
            while ($this->i < $this->n && ctype_digit($this->src[$this->i])) {
                $num .= $this->src[$this->i++];
            }
        }
        return new Token(Token::NUM, $num, $start, $space);
    }

    private function readIdent(bool $space, int $start): Token
    {
        $id = '';
        while ($this->i < $this->n && (ctype_alnum($this->src[$this->i]) || $this->src[$this->i] === '_')) {
            $id .= $this->src[$this->i++];
        }
        return new Token(Token::IDENT, $id, $start, $space);
    }

    private function readString(string $quote, bool $space, int $start): Token
    {
        $this->i++;
        $raw = '';
        while (true) {
            if ($this->i >= $this->n) {
                throw new ParseException('Unterminated string literal', $start);
            }
            $c = $this->src[$this->i];
            if ($c === '\\' && $this->i + 1 < $this->n) {
                $raw .= $c . $this->src[$this->i + 1];
                $this->i += 2;
                continue;
            }
            if ($c === $quote) {
                $this->i++;
                break;
            }
            $raw .= $c;
            $this->i++;
        }
        // Token value for strings is the *decoded* content.  Double quoted
        // interpolation is resolved by the parser, never by PHP itself.
        return new Token($quote === '"' ? 'dstr' : Token::STR, $raw, $start, $space);
    }

    public function peek(int $offset = 0): Token
    {
        return $this->tokens[min($this->i + $offset, count($this->tokens) - 1)];
    }
}
