<?php
declare(strict_types=1);

namespace TplGuard\Security;

/**
 * The set of things a template is permitted to do.
 *
 * A template's capability set is derived from *where the template came from*
 * and *who can edit it*, never from what the template writes.  This is the
 * heart of the fix for the reported vulnerability: a theme whose `viewthread`
 * template is editable by a forum moderator receives the SITE capability set,
 * which simply does not contain `php`, `eval`, dynamic calls, static access,
 * or arbitrary function invocation.
 */
final class Capabilities
{
    /** Run `{php}` / `{eval}` blocks. Essentially "root" — full PHP. */
    public const PHP = 'php';

    /** Call any function by name, e.g. `{system('id')}`. */
    public const ARBITRARY_CALL = 'arbitrary_call';

    /** Call a fixed allow-list of pure functions (count, strlen, ...). */
    public const SAFE_CALLS = 'safe_calls';

    /** `$a[$k]` with a runtime key — needed by some skins, enables probing. */
    public const DYNAMIC_INDEX = 'dynamic_index';

    /** Method calls `$obj->m()`. */
    public const METHOD_CALL = 'method_call';

    /** `$obj->prop` property reads. */
    public const PROPERTY_ACCESS = 'property_access';

    /** `Foo::BAR`, `Foo::$x`, `new Foo`. */
    public const STATIC_ACCESS = 'static_access';

    /** `{include $dynamic}` / `{template $name}`. */
    public const DYNAMIC_INCLUDE = 'dynamic_include';

    /** Plugin/custom tags. */
    public const PLUGIN_TAGS = 'plugin_tags';

    /** The `|eval:`-style modifier that runs PHP (some skins ship it). */
    public const EVAL_MODIFIER = 'eval_modifier';

    /**
     * Site-authored templates.  Moderators may reorganise markup and use all
     * the presentation features, but cannot reach PHP.
     */
    public const SITE = [
        self::SAFE_CALLS,
        self::DYNAMIC_INDEX,
        self::METHOD_CALL,
        self::PROPERTY_ACCESS,
        self::PLUGIN_TAGS,
    ];

    /** Anything a normal template may do without elevated trust. */
    public const MINIMAL = [
        self::SAFE_CALLS,
    ];

    /** Fully trusted code shipped by the vendor (capabilities: all). */
    public const TRUSTED = [
        self::PHP, self::ARBITRARY_CALL, self::SAFE_CALLS, self::DYNAMIC_INDEX,
        self::METHOD_CALL, self::PROPERTY_ACCESS, self::STATIC_ACCESS,
        self::DYNAMIC_INCLUDE, self::PLUGIN_TAGS, self::EVAL_MODIFIER,
    ];

    /**
     * Functions a template may call when it holds SAFE_CALLS.  Every entry is
     * pure (no I/O, no filesystem, no code execution, no reflection).  The
     * deny-list below is checked first and always wins.
     */
    public const SAFE_FUNCTIONS = [
        // string
        'strlen', 'strtolower', 'strtoupper', 'ucfirst', 'lcfirst', 'ucwords',
        'trim', 'ltrim', 'rtrim', 'substr', 'str_replace', 'str_ireplace',
        'str_pad', 'str_repeat', 'str_split', 'strrev', 'strpos', 'stripos',
        'strrpos', 'strstr', 'stristr', 'str_contains', 'str_starts_with',
        'str_ends_with', 'substr_count', 'wordwrap', 'nl2br', 'htmlspecialchars',
        'htmlentities', 'strip_tags', 'addslashes', 'stripslashes', 'quotemeta',
        'sprintf', 'vsprintf', 'number_format', 'chr', 'ord', 'implode', 'join',
        'explode', 'preg_match', 'preg_split', 'preg_quote',
        'md5', 'sha1', 'crc32', 'base64_encode', 'urlencode', 'urldecode',
        'rawurlencode', 'rawurldecode', 'http_build_query', 'parse_url',
        'soundex', 'metaphone', 'similar_text', 'levenshtein',
        'str_word_count', 'bin2hex', 'dechex', 'iconv',
        'mb_strlen', 'mb_substr', 'mb_strtolower', 'mb_strtoupper', 'mb_strpos',
        'mb_str_split', 'mb_convert_encoding', 'mb_detect_encoding',
        // numbers
        'abs', 'ceil', 'floor', 'round', 'intval', 'floatval', 'boolval',
        'strval', 'max', 'min', 'pow', 'sqrt', 'fmod', 'intdiv', 'base_convert',
        'bindec', 'decbin', 'hexdec', 'decoct', 'octdec',
        // arrays
        'count', 'sizeof', 'in_array', 'array_key_exists', 'array_keys',
        'array_values', 'array_merge', 'array_slice', 'array_splice',
        'array_search', 'array_reverse', 'array_unique', 'array_flip',
        'array_sum', 'array_product', 'array_map', 'array_filter', 'array_reduce',
        'array_combine', 'array_fill', 'array_pad', 'array_chunk', 'array_diff',
        'array_intersect', 'array_column', 'array_pop', 'array_shift',
        'array_key_first', 'array_key_last', 'range',
        // dates (pure formatting / parsing)
        'date', 'time', 'mktime', 'strtotime', 'checkdate', 'gmdate', 'idate',
        'getdate', 'localtime',
        // type checks
        'is_array', 'is_string', 'is_int', 'is_float', 'is_numeric', 'is_null',
        'is_bool', 'is_object', 'gettype', 'json_encode', 'json_decode',
    ];

    /**
     * Modifiers (`{$x|name:arg}`) permitted with SAFE_CALLS.  Each maps to a
     * pure callable provided by the runtime; see Runtime\Modifiers.
     */
    public const SAFE_FILTERS = [
        'escape', 'e', 'html', 'htmlspecialchars', 'htmlentities', 'raw', 'text',
        'strip_tags', 'strip', 'trim', 'nl2br', 'urlencode', 'urldecode',
        'url', 'rawurlencode', 'upper', 'lower', 'ucfirst', 'ucwords',
        'capitalize', 'length', 'strlen', 'count', 'substr', 'truncate', 'cutstr',
        'date', 'number_format', 'round', 'floor', 'ceil', 'intval', 'floatval',
        'default', 'json', 'json_encode', 'addslashes', 'stripslashes', 'md5',
        'base64', 'sprintf', 'replace', 'implode', 'join', 'split', 'pad',
        'repeat', 'reverse', 'keys', 'values', 'merge', 'slice', 'unique', 'sum',
        'sort', 'quote', 'nl2p', 'fix', 'html2text',
    ];

    /**
     * Functions that must NEVER be reachable from a template.  Checked before
     * SAFE_FUNCTIONS so an accidental duplicate in both lists stays blocked.
     * This is defence in depth: with capability checks the compiler never
     * emits a call to a name in this list, but keeping the list explicit
     * guards future edits to the allow-list.
     */
    public const DENY_FUNCTIONS = [
        'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru', 'popen',
        'proc_open', 'pcntl_exec', 'create_function', 'include', 'include_once',
        'require', 'require_once', 'file_get_contents', 'file_put_contents',
        'fopen', 'fwrite', 'fputs', 'fread', 'unlink', 'rmdir', 'mkdir',
        'rename', 'copy', 'chmod', 'chown', 'touch', 'tmpfile', 'tempnam',
        'symlink', 'link', 'readfile', 'glob', 'scandir', 'opendir', 'readdir',
        'getenv', 'putenv', 'phpinfo', 'phpversion', 'get_defined_vars',
        'get_defined_functions', 'get_defined_constants', 'get_loaded_extensions',
        'extract', 'parse_str', 'unserialize', 'call_user_func',
        'call_user_func_array', 'forward_static_call', 'forward_static_call_array',
        'func_get_args', 'constant', 'define', 'class_exists',
        'function_exists', 'method_exists', 'property_exists', 'is_a',
        'get_class', 'get_parent_class', 'get_object_vars', 'get_class_methods',
        'get_class_vars', 'var_dump', 'print_r', 'var_export',
        'debug_zval_dump', 'highlight_file', 'highlight_string', 'show_source',
        'error_log', 'trigger_error', 'set_error_handler',
        'set_exception_handler', 'register_shutdown_function',
        'register_tick_function', 'spl_autoload_register', 'session_start',
        'session_destroy', 'session_id', 'setcookie', 'header', 'headers_list',
        'headers_sent', 'mail', 'curl_exec', 'curl_init', 'fsockopen',
        'pfsockopen', 'stream_socket_client', 'socket_create', 'mysqli_query',
        'pg_query', 'gzinflate', 'gzuncompress', 'gzdecode', 'str_rot13',
    ];

    /** @param list<string> $caps */
    public static function has(array $caps, string $cap): bool
    {
        return in_array($cap, $caps, true);
    }

    public static function isDeniedFunction(string $name): bool
    {
        return in_array(strtolower($name), self::DENY_FUNCTIONS, true);
    }

    public static function isSafeFunction(string $name): bool
    {
        $l = strtolower($name);
        return in_array($l, self::SAFE_FUNCTIONS, true) && !in_array($l, self::DENY_FUNCTIONS, true);
    }

    public static function isSafeFilter(string $name): bool
    {
        return in_array(strtolower($name), self::SAFE_FILTERS, true);
    }
}
