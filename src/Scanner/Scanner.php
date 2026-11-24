<?php
declare(strict_types=1);

namespace TplGuard\Scanner;

use TplGuard\Parser\ParseException;
use TplGuard\Parser\ParserOptions;
use TplGuard\Parser\TemplateParser;
use TplGuard\Security\AnalysisResult;
use TplGuard\Security\Analyzer;
use TplGuard\Security\Capabilities;
use TplGuard\Security\Finding;

/**
 * Offline scanner for an existing skin/plugin tree.
 *
 * Run it *before* rollout to find the templates that the new policy would
 * refuse, so you can decide per template: rewrite it, move it to a more
 * trusted directory, or accept the (visible) rejection.  It never executes a
 * template; it parses and analyses only.
 */
final class Scanner
{
    /**
     * @param list<string> $capabilities policy to test against
     * @return list<array{file:string, ok:bool, findings:list<array>, excerpt:string}>
     */
    public function scanTree(string $root, array $capabilities = Capabilities::SITE, int $limit = 0): array
    {
        $results = [];
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $ext = strtolower($file->getExtension());
            if (!in_array($ext, ['html', 'htm', 'tpl'], true)) {
                continue;
            }
            $results[] = $this->scanFile($file->getPathname(), $capabilities);
            if ($limit > 0 && count($results) >= $limit) {
                break;
            }
        }
        return $results;
    }

    /** @return array{file:string, ok:bool, findings:list<array>, excerpt:string} */
    public function scanFile(string $path, array $capabilities = Capabilities::SITE): array
    {
        $src = (string) file_get_contents($path);
        try {
            $nodes = TemplateParser::parse($src, new ParserOptions(), []);
            $analysis = (new Analyzer($capabilities))->analyze($nodes);
        } catch (ParseException $e) {
            $analysis = new AnalysisResult(
                [new Finding(Finding::ERROR, 'parse', $e->getMessage(), 0)],
                false,
                false
            );
        }

        $findings = $analysis->toArray();
        // Include the offending source line for each finding so a reviewer can
        // jump straight to it without opening the file.
        $lines = preg_split('/\R/', $src) ?: [];
        foreach ($findings as &$f) {
            $n = (int) ($f['line'] ?? 0);
            $f['excerpt'] = $n > 0 && isset($lines[$n - 1]) ? trim($lines[$n - 1]) : '';
        }
        unset($f);

        return [
            'file' => $path,
            'ok' => $analysis->ok(),
            'findings' => $findings,
            'excerpt' => '',
        ];
    }

    /**
     * Report as a stable, diffable JSON document (for CI) or a short text
     * summary (for humans).
     *
     * @param list<array> $results
     */
    public function report(array $results, string $format = 'text'): string
    {
        $bad = array_values(array_filter($results, fn ($r) => !$r['ok']));
        if ($format === 'json') {
            return (string) json_encode(
                ['scanned' => count($results), 'failed' => count($bad), 'results' => $results],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
            );
        }
        $out = '';
        foreach ($bad as $r) {
            $out .= $r['file'] . "\n";
            foreach ($r['findings'] as $f) {
                if (($f['severity'] ?? '') !== Finding::ERROR) {
                    continue;
                }
                $out .= sprintf(
                    "  line %d  %-18s %s%s\n",
                    $f['line'] ?? 0,
                    $f['rule'] ?? '',
                    $f['message'] ?? '',
                    ($f['excerpt'] ?? '') !== '' ? '   | ' . $f['excerpt'] : ''
                );
            }
        }
        $out .= sprintf("\nScanned %d templates, %d would be refused.\n", count($results), count($bad));
        return $out;
    }
}
