<?php
declare(strict_types=1);

namespace TplGuard;

use TplGuard\Cache\CompiledCache;
use TplGuard\Cache\ResolutionIndex;
use TplGuard\Compiler\Compiler;
use TplGuard\Exception\SecurityViolation;
use TplGuard\Exception\TemplateException;
use TplGuard\Parser\ParseException;
use TplGuard\Parser\ParserOptions;
use TplGuard\Parser\TemplateParser;
use TplGuard\Runtime\Context;
use TplGuard\Runtime\CompiledTemplate;
use TplGuard\Runtime\Renderer;
use TplGuard\Security\AnalysisResult;
use TplGuard\Security\Analyzer;
use TplGuard\Security\Finding;
use TplGuard\Security\TrustPolicy;

/**
 * Front door: load a template under a trust policy, compile+cache it, render.
 *
 * Typical forum integration:
 *
 *   $engine = new Engine('/var/www/forum/data/template_cache', [
 *       \TplGuard\Security\TrustPolicy::vendor('/var/www/forum/template'),
 *       \TplGuard\Security\TrustPolicy::skin('/var/www/forum/data/skin'),
 *       \TplGuard\Security\TrustPolicy::site('/var/www/forum/data/template'),
 *   ]);
 *   $engine->render('forum/viewthread', ['thread' => $thread, ...]);
 *
 * The policy is chosen by which root the template file actually lives under —
 * a fact the request cannot influence.
 */
final class Engine
{
    /** @param list<TrustPolicy> $policies ordered; first matching root wins */
    public function __construct(
        private string $cacheDir,
        private array $policies,
        private ParserOptions $parserOptions = new ParserOptions(),
        /** @var array<string,true> */
        private array $pluginTags = [],
        /** @var callable(string,array,?string,Context):string|null */
        private $tagHandler = null,
        private int $compilerVersion = 0,
    ) {
        $this->cache = new CompiledCache($this->cacheDir, $compilerVersion > 0 ? $compilerVersion : null);
        $this->index = new ResolutionIndex();
    }

    private CompiledCache $cache;
    private ResolutionIndex $index;

    /**
     * Resolve a logical template name to its absolute file and policy.
     *
     * @return array{0:string,1:TrustPolicy}
     */
    public function resolve(string $name, ?TrustPolicy $forcePolicy = null): array
    {
        if (!preg_match('#^[A-Za-z0-9_][A-Za-z0-9_/.-]*$#', $name) || str_contains($name, '..')) {
            throw new TemplateException("Invalid template name: $name");
        }
        $policies = $forcePolicy !== null ? [$forcePolicy] : $this->policies;
        foreach ($policies as $policy) {
            // Compare against the *resolved* root so symlinked roots (e.g.
            // /tmp -> /private/tmp) and symlinks inside the tree are handled
            // consistently; the containment test still uses the real path.
            $base = realpath($policy->root);
            if ($base === false) {
                continue;
            }
            $base = rtrim($base, '/');
            foreach (['.html', '.htm', '.tpl', ''] as $ext) {
                $real = realpath($base . '/' . $name . $ext);
                if ($real !== false && is_file($real) && str_starts_with($real, $base . '/')) {
                    return [$real, $policy];
                }
            }
        }
        throw new TemplateException("Template not found: $name");
    }

    /** @param array<string,mixed> $vars */
    public function render(string $name, array $vars = []): string
    {
        $class = $this->classFor($name);
        $ctx = new Context($vars);
        /** @var CompiledTemplate $tpl */
        $tpl = new $class();
        if ($this->tagHandler === null) {
            // Fast path: a template with no plugin tags and no includes never
            // touches the renderer's callbacks.  Reuse one stateless instance.
            return $tpl->render($ctx, $this->renderer ??= new Renderer(null, 12));
        }
        $renderer = new Renderer($this->tagHandler, 12);
        $renderer->setTemplateResolver(fn (string $n, Context $c): string => $this->renderTemplate($n, $c));
        return $tpl->render($ctx, $renderer);
    }

    private ?Renderer $renderer = null;

    private function renderTemplate(string $name, Context $ctx): string
    {
        return $this->render($name, $ctx->vars);
    }

    /**
     * Hot path: resolve the template and return its compiled class without
     * reading the source, as long as the file's stat signature is unchanged.
     */
    private function classFor(string $name): string
    {
        $hit = $this->index->get($name);
        if ($hit !== null) {
            if (!ResolutionIndex::isValid($hit)) {
                $this->index->forget($name);
            } elseif (class_exists($hit['class'], false)) {
                return $hit['class'];
            } else {
                // First request in this worker (or OPcache evicted it):
                // require the already-compiled artifact, no re-analysis.
                $file = $this->cache->path($hit['key']);
                if (is_file($file)) {
                    require_once $file;
                    if (class_exists($hit['class'], false)) {
                        return $hit['class'];
                    }
                }
                $this->index->forget($name);
            }
        }

        [$file, $policy] = $this->resolve($name);
        $policyIx = array_search($policy, $this->policies, true);
        $policyIx = $policyIx === false ? -1 : (int) $policyIx;
        $st = @stat($file);
        if ($st === false) {
            throw new TemplateException("Unreadable template: $name");
        }
        $class = $this->loadClass($name, $file, $policy, $st);
        $this->index->put(
            $name,
            $file,
            $policyIx,
            $st['mtime'],
            $st['size'],
            $class,
            $this->cache->key($name, $this->hashOf($file, $st), $policy->capabilities),
        );
        return $class;
    }

    /** Content hash, memoised by the per-process file-stat signature. */
    private function hashOf(string $file, array $st): string
    {
        return hash('sha256', (string) file_get_contents($file));
    }

    /**
     * Compile-time analysis without compiling.  Used by the admin panel and
     * the scanner to explain a rejection before a template is ever saved.
     *
     * @return array{policy:string,analysis:AnalysisResult}
     */
    public function inspect(string $name, ?TrustPolicy $forcePolicy = null): array
    {
        [$file, $policy] = $this->resolve($name, $forcePolicy);
        $src = (string) file_get_contents($file);
        $nodes = $this->parse($src, $name);
        $analysis = (new Analyzer($policy->capabilities))->analyze($nodes);
        return ['policy' => $policy->name, 'analysis' => $analysis];
    }

    private function loadClass(string $name, string $file, TrustPolicy $policy, array $st): string
    {
        $src = (string) file_get_contents($file);
        $hash = hash('sha256', $src);

        return $this->cache->load(
            $name,
            $hash,
            $policy->capabilities,
            function () use ($name, $src, $policy, $hash): string {
                $nodes = $this->parse($src, $name);
                $analysis = (new Analyzer($policy->capabilities))->analyze($nodes);
                if (!$analysis->ok()) {
                    throw new SecurityViolation($name, $analysis);
                }
                $key = $this->cache->key($name, $hash, $policy->capabilities);
                $compiler = new Compiler(
                    $nodes,
                    $policy->capabilities,
                    $this->parserOptions,
                    'T_' . $key, // short name; the compiler emits namespaces
                    $hash,
                    $name,
                );
                return $compiler->compile();
            }
        );
    }

    /** @return list<\TplGuard\Ast\Node> */
    private function parse(string $src, string $name): array
    {
        try {
            return TemplateParser::parse($src, $this->parserOptions, $this->pluginTags);
        } catch (ParseException $e) {
            $analysis = new AnalysisResult(
                [new Finding(Finding::ERROR, 'parse', $e->getMessage(), 1)],
                false,
                false
            );
            throw new SecurityViolation($name, $analysis);
        }
    }

    private function buildTagHandler(): ?callable
    {
        return $this->tagHandler;
    }
}
