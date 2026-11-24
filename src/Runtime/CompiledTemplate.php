<?php
declare(strict_types=1);

namespace TplGuard\Runtime;

/** Base class for every compiled template. */
abstract class CompiledTemplate
{
    public const SOURCE_HASH = '';
    public const TEMPLATE_NAME = '';

    abstract public function render(Context $ctx, Renderer $r): string;
}
