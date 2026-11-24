<?php
declare(strict_types=1);

namespace TplGuard\Parser;

final class ParserOptions
{
    public function __construct(
        /**
         * How a bare `.` between two operands is read.
         *  - 'key'    : legacy Discuz style, `$a.b` = `$a['b']`
         *  - 'concat' : PHP style, `$a . $b` = string concatenation
         *  - 'auto'   : key-access only when written without surrounding
         *               spaces (`$a.b`), concat otherwise (`$a . $b`)
         */
        public string $dotSyntax = 'auto',

        /** Tag delimiters for the block parser. */
        public string $open = '{',
        public string $close = '}',

        /** Allow `{php}...{/php}` and `{eval}` blocks to be *parsed*. */
        public bool $allowPhpBlocks = true,
    ) {}
}
