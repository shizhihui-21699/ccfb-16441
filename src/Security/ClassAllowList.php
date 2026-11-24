<?php
declare(strict_types=1);

namespace TplGuard\Security;

/**
 * Explicit allow-list of members, keyed by class name (or interface).
 *
 *   new ClassAllowList(
 *       methods:    [\App\Forum\User::class => ['getDisplayName', 'isAdmin']],
 *       properties: [\App\Forum\User::class => ['username', 'avatarUrl']],
 *   );
 *
 * A template may only call/read members listed for a class the object *is*
 * (`instanceof`, so subclasses work).  Everything else is refused, and the
 * runtime refuses at call time even if the analyzer let the syntax through.
 */
final class ClassAllowList implements MemberPolicy
{
    /**
     * @param array<class-string, list<string>> $methods
     * @param array<class-string, list<string>> $properties
     */
    public function __construct(
        private array $methods = [],
        private array $properties = [],
    ) {}

    public function allowsMethod(object $object, string $method): bool
    {
        if ($method === '' || $method[0] === '_') {
            return false;
        }
        foreach ($this->methods as $class => $allowed) {
            if ($object instanceof $class && in_array($method, $allowed, true)) {
                return true;
            }
        }
        return false;
    }

    public function allowsProperty(object $object, string $property): bool
    {
        if ($property === '' || $property[0] === '_') {
            return false;
        }
        foreach ($this->properties as $class => $allowed) {
            if ($object instanceof $class && in_array($property, $allowed, true)) {
                return true;
            }
        }
        return false;
    }
}
