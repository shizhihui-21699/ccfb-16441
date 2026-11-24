<?php
declare(strict_types=1);

namespace TplGuard\Parser;

final class ParseException extends \RuntimeException
{
    public function __construct(string $message, public int $offset = 0)
    {
        parent::__construct($message);
    }
}
