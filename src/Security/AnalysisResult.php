<?php
declare(strict_types=1);

namespace TplGuard\Security;

/** Result of analysing one template against one capability set. */
final class AnalysisResult
{
    /** @param list<Finding> $findings */
    public function __construct(
        public array $findings,
        public bool $usedPhp,
        public bool $usedDynamicCall,
    ) {}

    public function ok(): bool
    {
        foreach ($this->findings as $f) {
            if ($f->severity === Finding::ERROR) {
                return false;
            }
        }
        return true;
    }

    /** @return list<Finding> */
    public function errors(): array
    {
        return array_values(array_filter($this->findings, fn (Finding $f) => $f->severity === Finding::ERROR));
    }

    /** @return list<Finding> */
    public function warnings(): array
    {
        return array_values(array_filter($this->findings, fn (Finding $f) => $f->severity === Finding::WARNING));
    }

    /** @return list<array> */
    public function toArray(): array
    {
        return array_map(fn (Finding $f) => $f->toArray(), $this->findings);
    }
}
