<?php
declare(strict_types=1);

namespace TplGuard\Runtime;

use TplGuard\Exception\TemplateException;

/**
 * Per-request rendering state: template lookup for includes, plugin tag
 * dispatch, and the small primitives compiled code uses (`out`, `dig`,
 * `iterable`, `concat`, `binop`).
 */
final class Renderer
{
    /**
     * @param callable(string,array,?string,Context):string $tagHandler
     *        Called as $handler($tagName, $attrs, $body, $ctx)
     */
    public function __construct(
        private $tagHandler,
        private int $maxIncludeDepth = 12,
        private int $depth = 0,
        private ?\TplGuard\Security\MemberPolicy $members = null,
    ) {}

    /**
     * Invoke an object method, but only when the member policy permits it for
     * this object's class, the method is public and non-magic, and its
     * parameters are declarable from template values (scalars/arrays/null —
     * never a callable, which could be invoked inside the method).
     *
     * @param list<mixed> $args
     */
    public function callMethod(mixed $object, string $method, array $args, Context $ctx): mixed
    {
        if (!is_object($object) || $this->members === null) {
            return null;
        }
        if (!$this->members->allowsMethod($object, $method)) {
            return null;
        }
        if (!method_exists($object, $method)) {
            return null;
        }
        try {
            $ref = new \ReflectionMethod($object, $method);
        } catch (\ReflectionException) {
            return null;
        }
        if (!$ref->isPublic() || $ref->isStatic() || $ref->isAbstract()) {
            return null;
        }
        foreach ($args as $a) {
            if (!is_scalar($a) && $a !== null && !is_array($a)) {
                return null; // never hand a callable / object to the method
            }
            // A string that names a function is a callable; if the method
            // forwards it to `$arg(...)` that is code execution.  Refuse any
            // argument that PHP would treat as a callable.
            if (is_string($a) && $a !== '' && is_callable($a)) {
                return null;
            }
        }
        return $object->{$method}(...$args);
    }

    /**
     * Echo a value with PHP 8 `echo` semantics exactly, minus the warnings
     * legacy templates routinely trigger (`Array to string conversion`).
     * Matching byte-for-byte is what lets the differential suite prove old
     * skins render unchanged.
     */
    public static function out(mixed $v): string
    {
        if (is_string($v)) {
            return $v;
        }
        if (is_int($v)) {
            return (string) $v;
        }
        if (is_float($v)) {
            return self::floatToString($v);
        }
        if (is_bool($v)) {
            return $v ? '1' : '';
        }
        if ($v === null) {
            return '';
        }
        if (is_array($v)) {
            // PHP 8 emits E_WARNING "Array to string conversion" and prints
            // "Array"; reproduce the bytes, not the warning.
            return 'Array';
        }
        if (is_object($v)) {
            // Never call __toString(): it is a magic method on a
            // template-inaccessible object and a potential gadget.  Objects
            // are not printable in a template; output nothing.
            return '';
        }
        return '';
    }

    /** Legacy `echo` float formatting matches `(string)$f` in PHP 8 closely. */
    private static function floatToString(float $f): string
    {
        if (is_nan($f)) {
            return 'NAN';
        }
        if (is_infinite($f)) {
            return $f > 0 ? 'INF' : '-INF';
        }
        if ($f === floor($f) && abs($f) < 1e15) {
            return (string) (int) $f;
        }
        return (string) $f;
    }

    public static function concat(mixed $a, mixed $b): string
    {
        return self::scalar($a) . self::scalar($b);
    }

    private static function scalar(mixed $v): string
    {
        if (is_array($v)) {
            return 'Array';
        }
        return self::out($v);
    }

    public static function iterable(mixed $v): array
    {
        if (is_array($v)) {
            return $v;
        }
        if ($v instanceof \Traversable) {
            return iterator_to_array($v, true);
        }
        return [];
    }

    public static function binop(string $op, mixed $l, mixed $r): mixed
    {
        return match ($op) {
            '===' => $l === $r,
            '!==' => $l !== $r,
            '<=>' => $l <=> $r,
            '**' => $l ** $r,
            '|' => (int) $l | (int) $r,
            '&' => (int) $l & (int) $r,
            default => throw new \LogicException("Unknown operator $op"),
        };
    }

    /**
     * Render another template.  The lookup goes through the same policy-driven
     * loader as the request, so an include cannot escape the capability model.
     *
     * @param array<string,mixed> $params
     */
    public function include(mixed $name, array $params, ?Context $parent = null): string
    {
        if (!is_string($name) || $name === '') {
            return '';
        }
        if ($this->depth >= $this->maxIncludeDepth) {
            throw new TemplateException("Template include depth exceeded at '$name'");
        }
        $this->depth++;
        try {
            // Legacy engines rendered an include in the *caller's* scope with
            // the explicit params merged on top; preserve that.
            $vars = $parent?->vars ?? [];
            foreach ($params as $k => $v) {
                $vars[$k] = $v;
            }
            $child = new Context($vars);
            return $this->renderTemplate($name, $child);
        } finally {
            $this->depth--;
        }
    }

    /**
     * @param array<string,mixed> $attrs
     */
    public function tag(string $name, array $attrs, ?string $body, Context $ctx): string
    {
        $handler = $this->tagHandler;
        if ($handler === null) {
            return '';
        }
        return (string) $handler($name, $attrs, $body, $ctx);
    }

    public function setMemberPolicy(\TplGuard\Security\MemberPolicy $members): void
    {
        $this->members = $members;
    }

    /** @var null|\Closure(string,Context):string */
    private ?\Closure $templateResolver = null;

    public function setTemplateResolver(\Closure $resolver): void
    {
        $this->templateResolver = $resolver;
    }

    private function renderTemplate(string $name, Context $ctx): string
    {
        if ($this->templateResolver === null) {
            throw new TemplateException('No template resolver configured for includes');
        }
        return ($this->templateResolver)($name, $ctx);
    }
}
