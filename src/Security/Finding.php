<?php
declare(strict_types=1);

namespace TplGuard\Security;

/** One reason a template was rejected or flagged. */
final class Finding
{
    public const ERROR = 'error';       // template must not be loaded
    public const WARNING = 'warning';   // loaded, but logged / reviewed

    public function __construct(
        public string $severity,
        public string $rule,
        public string $message,
        public int $line = 0,
        public string $snippet = '',
    ) {}

    public function toArray(): array
    {
        return [
            'severity' => $this->severity,
            'rule' => $this->rule,
            'message' => $this->message,
            'line' => $this->line,
            'snippet' => $this->snippet,
        ];
    }

    public function __toString(): string
    {
        return sprintf('[%s] %s: %s (line %d)', strtoupper($this->severity), $this->rule, $this->message, $this->line);
    }
}
