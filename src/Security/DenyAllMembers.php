<?php
declare(strict_types=1);

namespace TplGuard\Security;

/** Refuses every object member access.  The default for site/skin templates. */
final class DenyAllMembers implements MemberPolicy
{
    public function allowsMethod(object $object, string $method): bool
    {
        return false;
    }

    public function allowsProperty(object $object, string $property): bool
    {
        return false;
    }
}
