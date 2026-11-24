<?php
declare(strict_types=1);

namespace TplGuard\Security;

/**
 * Decides which object members (`$obj->prop`, `$obj->method()`) a template in
 * a non-trusted tier may touch.
 *
 * Blanket member access is as dangerous as calling arbitrary functions: any
 * object graph the controller hands to a template can contain a gadget
 * (`$obj->logger->write($cmd)`, a `Pdo` handle, a `Closure`).  So member
 * access is deny-by-default and must be granted by an explicit allow-list of
 * *class => members* — the same shape as a Twig sandbox policy.
 *
 * The vendor tier does not consult this policy at all (it holds the
 * `static_access` capability and is trusted code).
 */
interface MemberPolicy
{
    public function allowsMethod(object $object, string $method): bool;

    public function allowsProperty(object $object, string $property): bool;
}
