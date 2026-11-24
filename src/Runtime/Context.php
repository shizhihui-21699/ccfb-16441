<?php
declare(strict_types=1);

namespace TplGuard\Runtime;

use TplGuard\Security\DenyAllMembers;
use TplGuard\Security\MemberPolicy;

/**
 * Variable scope handed to a compiled template.
 *
 * Variable access never uses PHP's `extract()`/`compact()`: compiled code
 * reads through this object, so a template cannot reach a local variable of
 * the surrounding controller (the classic `{$_SERVER}` / `{$GLOBALS}`
 * escalation path) — only names the caller explicitly passed can be read.
 *
 * Object member reads go through a MemberPolicy (deny-by-default): a template
 * cannot walk an object graph the controller passed in and reach a gadget.
 */
final class Context
{
    /** Never resolvable as a template variable, whatever the caller passes. */
    private const BLOCKED_ROOTS = [
        '_SERVER', '_ENV', '_GET', '_POST', '_COOKIE', '_FILES', '_REQUEST',
        '_SESSION', 'GLOBALS', 'argv', 'argc', 'this',
    ];

    /** @param array<string,mixed> $vars */
    public function __construct(
        public array $vars = [],
        private MemberPolicy $members = new DenyAllMembers(),
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

    /**
     * Read a static path such as `user.profile.name`, compiled to
     * `resolve('user', ['profile', 'name'])`.
     *
     * @param list<int|string> $path
     */
    public function resolve(string $root, array $path): mixed
    {
        if (in_array($root, self::BLOCKED_ROOTS, true)) {
            return null;
        }
        $v = $this->vars[$root] ?? null;
        foreach ($path as $key) {
            $v = $this->dig($v, $key);
            if ($v === null) {
                return null;
            }
        }
        return $v;
    }

    /**
     * Index into an array / string, or read an allowed object property.
     *
     * Object property reads are gated by the member policy; arrays and strings
     * are inert and need no policy.
     */
    public function dig(mixed $v, int|string $key): mixed
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
            return $this->readProperty($v, (string) $key);
        }
        return null;
    }

    /**
     * Read a property only when the member policy allows it for this object's
     * class.  Never triggers `__get()` and never returns non-public state.
     */
    public function readProperty(object $object, string $name): mixed
    {
        if (!$this->members->allowsProperty($object, $name)) {
            return null;
        }
        if (property_exists($object, $name)) {
            $vars = get_object_vars($object); // public scope only
            return $vars[$name] ?? null;
        }
        return null;
    }
}
