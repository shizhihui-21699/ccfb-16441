<?php
declare(strict_types=1);

namespace TplGuard\Cache;

/**
 * Compiled-template cache.
 *
 * Two things matter for a forum doing millions of hits a day:
 *
 *  1. The hot path must be a single `filemtime`/`hash` check plus `require`.
 *     No parsing, no analysis, no reflection.
 *  2. Writes must be atomic, because several FPM workers may compile the same
 *     template at once.  We write to a temp file in the same directory and
 *     `rename()` (atomic on POSIX).  A half-written file can never be
 *     `require`d — a fatal error in a compiled template would take the whole
 *     worker down.
 *
 * The cache key includes the capability set, so the same source compiled for
 * two trust levels can never be served to the wrong one.
 */
final class CompiledCache
{
    public function __construct(
        private string $dir,
        /**
         * Invalidates every artifact when the compiler/runtime changes.
         * Defaults to the newest mtime of the engine sources, so a deploy
         * that touches any src/*.php file cannot silently keep serving code
         * compiled by the previous version.
         */
        ?int $compilerVersion = null,
    ) {
        $this->compilerVersion = $compilerVersion ?? self::deriveVersion();
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0775, true) && !is_dir($this->dir)) {
            throw new \RuntimeException("Cannot create cache dir {$this->dir}");
        }
    }

    private int $compilerVersion;

    private static function deriveVersion(): int
    {
        static $v = null;
        if ($v !== null) {
            return $v;
        }
        $max = 0;
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(__DIR__, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $f) {
            if ($f->isFile() && $f->getExtension() === 'php') {
                $max = max($max, $f->getMTime());
            }
        }
        return $v = $max ?: 1;
    }

    /**
     * @param list<string> $caps
     */
    public function key(string $templateName, string $sourceHash, array $caps): string
    {
        $caps = $caps;
        sort($caps);
        return hash('xxh128', implode("\0", [
            $this->compilerVersion,
            $templateName,
            $sourceHash,
            implode(',', $caps),
        ]));
    }

    public function path(string $key): string
    {
        return $this->dir . '/' . substr($key, 0, 2) . '/' . $key . '.php';
    }

    /**
     * @param list<string> $caps
     */
    public function classFor(string $key): string
    {
        return 'TplGuard\\Compiled\\T_' . $key;
    }

    /**
     * Return the compiled class for a template, compiling if needed.
     *
     * @param callable():string $compile   returns PHP source
     * @param list<string>      $caps
     */
    public function load(string $templateName, string $sourceHash, array $caps, callable $compile): string
    {
        $key = $this->key($templateName, $sourceHash, $caps);
        $class = $this->classFor($key);
        if (class_exists($class, false)) {
            return $class;
        }

        $file = $this->path($key);
        if (is_file($file)) {
            require $file;
            if (class_exists($class, false)) {
                return $class;
            }
            // A corrupt artifact: fall through and rebuild.
            @unlink($file);
        }

        $source = $compile();
        $this->writeAtomic($file, $source);
        require $file;
        if (!class_exists($class, false)) {
            throw new \RuntimeException("Compiled template {$templateName} did not define {$class}");
        }
        return $class;
    }

    private function writeAtomic(string $file, string $source): void
    {
        $dir = dirname($file);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new \RuntimeException("Cannot create cache subdir {$dir}");
        }
        $tmp = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
        $fh = @fopen($tmp, 'xb');
        if ($fh === false) {
            throw new \RuntimeException("Cannot open temp file {$tmp}");
        }
        try {
            if (fwrite($fh, $source) !== strlen($source)) {
                throw new \RuntimeException("Short write to {$tmp}");
            }
            fflush($fh);
            if (function_exists('fsync')) {
                @fsync($fh);
            }
        } finally {
            fclose($fh);
        }
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException("Cannot rename {$tmp} to {$file}");
        }
        // Best-effort: keep OPcache from thrashing between versions.
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
    }

    /** Warm the cache ahead of traffic (deploy step / admin save). */
    public function clear(): void
    {
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $f) {
            $path = $f->getPathname();
            $f->isDir() ? @rmdir($path) : @unlink($path);
        }
    }
}
