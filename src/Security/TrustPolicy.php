<?php
declare(strict_types=1);

namespace TplGuard\Security;

/**
 * Where a template came from and who may edit it.  Trust is assigned by the
 * *storage layer*, from server-side facts — never from anything stored inside
 * the template, and never from the editor's POST body.
 */
final class TrustPolicy
{
    /**
     * @param string       $name         policy name (for logging)
     * @param list<string> $capabilities capability set granted to matching templates
     * @param string       $root         absolute template root directory
     * @param bool         $isEditable   whether non-admins can edit templates here
     */
    public function __construct(
        public string $name,
        public array $capabilities,
        public string $root,
        public bool $isEditable,
    ) {}

    /** Vendor-shipped template, never writable from the admin panel. */
    public static function vendor(string $root): self
    {
        return new self('vendor', Capabilities::TRUSTED, $root, false);
    }

    /**
     * Site-authored template (owner/installer).  Still no PHP unless the
     * operator explicitly opts in — a hacked admin account should not mean
     * instant RCE through a stored template.
     */
    public static function site(string $root): self
    {
        return new self('site', Capabilities::SITE, $root, true);
    }

    /** A theme/skin uploaded by a third party or by a moderator. */
    public static function skin(string $root): self
    {
        return new self('skin', Capabilities::MINIMAL, $root, true);
    }

    public static function custom(string $name, array $caps, string $root): self
    {
        return new self($name, $caps, $root, true);
    }
}
