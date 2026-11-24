<?php
declare(strict_types=1);

namespace TplGuard\Exception;

use TplGuard\Security\AnalysisResult;

/**
 * Thrown at compile time when a template asks for a capability its trust
 * policy does not grant.  Carries the findings so the admin panel can show
 * the template author exactly which tag/line was refused.
 */
final class SecurityViolation extends TemplateException
{
    public function __construct(
        public string $templateName,
        public AnalysisResult $analysis,
    ) {
        $first = $analysis->errors()[0] ?? null;
        parent::__construct(sprintf(
            'Template "%s" was rejected: %s',
            $templateName,
            $first ? (string) $first : 'policy violation'
        ));
    }
}
