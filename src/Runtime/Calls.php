<?php
declare(strict_types=1);

namespace TplGuard\Runtime;

/**
 * Restricted callable helpers used by compiled templates.
 *
 * Compiled code calls these with *literal* names chosen by the compiler, so
 * no template string is ever used as a callable at runtime.  The runtime
 * re-checks the deny-list anyway (defence in depth against a compiler bug).
 */
final class Calls
{
    /**
     * Call a function the compiler approved.  The name arrives as a literal
     * from generated code, never from template input.
     *
     * @param list<mixed> $args
     */
    public static function fn(string $name, array $args): mixed
    {
        static $deny = null;
        $deny ??= array_flip(\TplGuard\Security\Capabilities::DENY_FUNCTIONS);
        if (isset($deny[strtolower($name)])) {
            throw new \LogicException("Function {$name}() is blocked");
        }
        // The only call site that reaches user-named functions.  Compiler
        // only emits this for {php}/arbitrary-call templates.
        return $name(...$args);
    }

    /**
     * Call an allow-listed ("safe") function from a non-trusted template.
     *
     * The name is a literal from generated code, but the *arguments* come from
     * the template and may include strings.  Refuse any argument that PHP
     * would treat as a callable so a higher-order function cannot be turned
     * into a trampoline, and re-apply the deny-list.  This mirrors the
     * analyzer so a future allow-list edit cannot reopen the callback hole.
     *
     * @param list<mixed> $args
     */
    public static function safe(string $name, array $args): mixed
    {
        static $deny = null;
        $deny ??= array_flip(\TplGuard\Security\Capabilities::DENY_FUNCTIONS);
        $lower = strtolower(ltrim($name, '\\'));
        if (isset($deny[$lower]) || !\TplGuard\Security\Capabilities::isSafeFunction($lower)) {
            throw new \LogicException("Function {$name}() is not permitted");
        }
        foreach ($args as $a) {
            if (self::looksCallable($a)) {
                throw new \LogicException("Callable argument to {$name}() is not permitted");
            }
        }
        return $name(...$args);
    }

    private static function looksCallable(mixed $v): bool
    {
        if (is_object($v) && !($v instanceof \Stringable)) {
            return true; // objects (incl. Closures, class-string holders)
        }
        if (is_string($v)) {
            return $v !== '' && is_callable($v);
        }
        if (is_array($v)) {
            // `[object, 'method']` / `['Class', 'staticMethod']` callable arrays
            if (count($v) === 2 && isset($v[1]) && is_string($v[1])) {
                [$a, $b] = $v;
                return (is_object($a) || is_string($a)) && is_callable([$a, $b]);
            }
            foreach ($v as $item) {
                if (self::looksCallable($item)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Call a method on an object.  Restricted to public methods whose names
     * do not begin with an underscore; arguments are passed as-is.  Only
     * emitted for templates holding the METHOD_CALL capability.
     *
     * @param list<mixed> $args
     */
    public static function method(mixed $obj, string $method, array $args): mixed
    {
        if (!is_object($obj) || $method === '' || $method[0] === '_') {
            return null;
        }
        if (!method_exists($obj, $method)) {
            return null;
        }
        $ref = new \ReflectionMethod($obj, $method);
        if (!$ref->isPublic() || $ref->isStatic()) {
            return null;
        }
        // Only zero-argument or scalar-argument calls, matching legacy skins.
        return $obj->{$method}(...$args);
    }

    /**
     * Invoke a computed callable.  Only reachable from templates holding the
     * ARBITRARY_CALL capability (trusted vendor code); refuses strings that
     * name a denied function.
     *
     * @param list<mixed> $args
     */
    public static function call(mixed $fn, array $args): mixed
    {
        if (is_string($fn)) {
            static $deny = null;
            $deny ??= array_flip(\TplGuard\Security\Capabilities::DENY_FUNCTIONS);
            if (isset($deny[strtolower($fn)]) || !function_exists($fn)) {
                return null;
            }
        }
        if (!is_callable($fn)) {
            return null;
        }
        return $fn(...$args);
    }
}
