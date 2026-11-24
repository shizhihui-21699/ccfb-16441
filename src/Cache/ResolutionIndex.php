<?php
declare(strict_types=1);

namespace TplGuard\Cache;

/**
 * In-process memoisation of resolved template metadata.
 *
 * A long-lived FPM worker serves the same handful of templates thousands of
 * times.  Without this the engine would re-scan template roots and re-read +
 * hash every template source on each request just to prove nothing changed.
 *
 * The key insight is that *change detection* does not need the file contents:
 * `stat()` (mtime + size + inode) is enough to notice an edit, and OPcache
 * already invalidates the compiled artifact by the same signal.  So the hot
 * path becomes one stat plus a class lookup — and, importantly, it is still
 * correct: an edited template gets a new key and is re-analysed before it can
 * be rendered.
 *
 * The index is per-process and never persisted, so a stale entry can only live
 * as long as the worker, and only for a file whose mtime and size did not
 * change.
 */
final class ResolutionIndex
{
    /**
     * @var array<string, array{file:string, policy:int, mtime:int, size:int, class:string, key:string}>
     */
    private array $entries = [];

    public function get(string $name): ?array
    {
        return $this->entries[$name] ?? null;
    }

    public function put(string $name, string $file, int $policyIx, int $mtime, int $size, string $class, string $key): void
    {
        $this->entries[$name] = [
            'file' => $file,
            'policy' => $policyIx,
            'mtime' => $mtime,
            'size' => $size,
            'class' => $class,
            'key' => $key,
        ];
    }

    /**
     * True when the cached entry still describes the file on disk.
     * `stat()` results are cached by PHP's stat cache, so this is very cheap.
     */
    public static function isValid(array $entry): bool
    {
        clearstatcache(true, $entry['file']);
        $st = @stat($entry['file']);
        return $st !== false && $st['mtime'] === $entry['mtime'] && $st['size'] === $entry['size'];
    }

    public function forget(string $name): void
    {
        unset($this->entries[$name]);
    }

    public function clear(): void
    {
        $this->entries = [];
    }
}
