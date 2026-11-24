<?php
declare(strict_types=1);

namespace TplGuard\Runtime;

/**
 * Variable scope handed to a compiled template.
 *
 * Variable access never uses PHP's `extract()`/`compact()`: compiled code
 * reads through this object, so a template cannot reach a local variable of
 * the surrounding controller (the classic `{$_SERVER}` / `{$GLOBALS}`
 * escalation path) — only names the caller explicitly passed can be read.
 *
 * Even if a controller *does* pass a superglobal array in, reading it through
 * the usual name returns null: templates must not see `$_SERVER`,
 * `$_ENV`, `$_SESSION` and friends directly.  This is the single most useful
 * primitive for SSTI, because it leaks filesystem paths, credentials in the
 * environment, and session data.
 */
final class Context
{
    /** Never resolvable as a template variable, whatever the caller passes. */
    private const BLOCKED_ROOTS = [
        '_SERVER', '_ENV', '_GET', '_POST', '_COOKIE', '_FILES', '_REQUEST',
        '_SESSION', 'GLOBALS', 'argv', 'argc', 'this',
    ];

    /**
     * @param array<string,mixed> $vars
     * @param bool $allowSuperglobals only for a trusted/admin template when an
     *        operator deliberately opts in (see TrustPolicy)
     */
    public function __construct(
        public array $vars = [],
        private bool $allowSuperglobals = false,
    ) {}

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->vars);
    }

    public function get(string $name): mixed
    {
        return $this->vars[$name] ?? null;
    }

    public function set(string $name, mixed $value): void
    {
        $this->vars[$name] = $value;
    }

    public function unset(string $name): void
    {
        unset($this->vars[$name]);
    }

    private function isBlocked(string $root): bool
    {
        return !$this->allowSuperglobals && in_array($root, self::BLOCKED_ROOTS, true);
    }

    /**
     * Read a static path such as `user.profile.name`, compiled to
     * `resolve('user', ['profile', 'name'])`.
     *
     * @param list<int|string> $path
     */
    public function resolve(string $root, array $path): mixed
    {
        if ($this->isBlocked($root)) {
            return null;
        }
        $v = $this->vars[$root] ?? null;
        foreach ($path as $key) {
            $v = self::dig($v, $key);
            if ($v === null) {
                return null;
            }
        }
        return $v;
    }

    /**
     * Index into array / string / public object property without warnings and
     * without ever invoking user code (`__get`, `__call`, string callables).
     */
    public static function dig(mixed $v, int|string $key): mixed
    {
        if (is_array($v)) {
            return $v[$key] ?? null;
        }
        if (is_string($v)) {
            $i = is_int($key) ? $key : (preg_match('/^-?\d+$/', (string) $key) ? (int) $key : null);
            if ($i !== null) {
                return ($i >= 0 && $i < strlen($v)) ? $v[$i] : null;
            }
            return null;
        }
        if (is_object($v)) {
            return self::readProperty($v, (string) $key);
        }
        return null;
    }

    /**
     * Read a *public, already-declared* property.  `get_object_vars()` from
     * outside the class sees only public properties and does not trigger
     * `__get()`; both properties are required for the read to succeed.
     */
    public static function readProperty(object $obj, string $name): mixed
    {
        if ($name === '' || $name[0] === '_') {
            return null; // no magic / private access
        }
        if ($obj instanceof \Closure) {
            return null;
        }
        if (property_exists($obj, $name)) {
            $vars = get_object_vars($obj); // public scope only
            return $vars[$name] ?? null;
        }
        if ($obj instanceof \ArrayAccess && $obj instanceof \ArrayObject) {
            return $obj[$name] ?? null;
        }
        return null;
    }
}
