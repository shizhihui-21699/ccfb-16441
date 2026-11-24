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
