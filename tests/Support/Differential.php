<?php
declare(strict_types=1);

namespace TplGuard\Tests\Support;

use TplGuard\Engine;
use TplGuard\Security\TrustPolicy;

/**
 * Renders one template through both the hardened engine and the legacy
 * reference interpreter and returns both outputs, so tests can compare.
 */
final class Differential
{
    private static int $seq = 0;

    public function __construct(
        private string $workDir,
        private TrustPolicy $policy,
    ) {}

    /**
     * @param array<string,mixed> $vars
     * @return array{0:string,1:string} [hardened, legacy]
     */
    public function run(string $template, array $vars = []): array
    {
        $id = 't' . (++self::$seq) . '_' . bin2hex(random_bytes(4));
        $dir = $this->workDir . '/' . $id;
        @mkdir($dir, 0777, true);
        file_put_contents($dir . '/page.html', $template);

        // Both sides must see the same policy roots; the engine resolves the
        // template by walking the policy directory.
        $engine = new Engine(
            $this->workDir . '/cache_' . $id,
            [new TrustPolicy($this->policy->name, $this->policy->capabilities, $dir, $this->policy->isEditable)],
        );
        $hardened = $engine->render('page', $vars);

        $legacy = (new LegacyReference())->render($template, $vars);

        return [$hardened, $legacy];
    }
}
