<?php
declare(strict_types=1);

namespace TplGuard\Runtime;


/**
 * Pure implementations of the `|modifier` vocabulary.  Compiled templates
 * never call `$name(...)` on a template-supplied string; the compiler emits a
 * direct call to one of these static methods, chosen from a fixed table.
 */
final class Modifiers
{
    public static function apply(string $name, mixed $value, array $args = []): mixed
    {
        return match (strtolower($name)) {
            'escape', 'e', 'html', 'htmlspecialchars' => htmlspecialchars(
                self::str($value),
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8'
            ),
            'htmlentities' => htmlentities(self::str($value), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            'raw', 'text' => $value,
            'strip_tags', 'strip' => strip_tags(self::str($value)),
            'trim' => trim(self::str($value)),
            'nl2br' => nl2br(self::str($value)),
            'urlencode' => urlencode(self::str($value)),
            'urldecode' => urldecode(self::str($value)),
            'url', 'rawurlencode' => rawurlencode(self::str($value)),
            'upper' => self::mb('mb_strtoupper', $value),
            'lower' => self::mb('mb_strtolower', $value),
            'ucfirst' => ucfirst(self::str($value)),
            'ucwords' => ucwords(self::str($value)),
            'capitalize' => ucwords(self::mb('mb_strtolower', $value)),
            'length', 'strlen' => is_array($value) ? count($value) : self::mb('mb_strlen', $value),
            'count' => is_array($value) ? count($value) : (is_object($value) ? count(get_object_vars($value)) : 0),
            'substr', 'truncate', 'cutstr' => self::truncate($value, (int) ($args[0] ?? 0), (int) ($args[1] ?? 0)),
            'date' => self::date(self::str($args[0] ?? 'Y-m-d'), $value),
            'number_format' => number_format((float) $value, (int) ($args[0] ?? 0), '.', ','),
            'round' => round((float) $value, (int) ($args[0] ?? 0)),
            'floor' => floor((float) $value),
            'ceil' => ceil((float) $value),
            'intval' => (int) $value,
            'floatval' => (float) $value,
            'default' => ($value === null || $value === '' || $value === []) ? ($args[0] ?? '') : $value,
            'json', 'json_encode' => json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'addslashes' => addslashes(self::str($value)),
            'stripslashes' => stripslashes(self::str($value)),
            'md5' => md5(self::str($value)),
            'base64' => base64_encode(self::str($value)),
            'sprintf' => vsprintf(self::str($args[0] ?? ''), array_merge([$value], array_slice($args, 1))),
            'replace' => str_replace(self::str($args[0] ?? ''), self::str($args[1] ?? ''), self::str($value)),
            'implode', 'join' => is_array($value) ? implode(self::str($args[0] ?? ''), $value) : self::str($value),
            'split' => explode(self::str($args[0] ?? ','), self::str($value)),
            'pad' => str_pad(self::str($value), (int) ($args[0] ?? 0), self::str($args[1] ?? ' '), (int) ($args[2] ?? STR_PAD_RIGHT)),
            'repeat' => str_repeat(self::str($value), max(0, (int) ($args[0] ?? 1))),
            'reverse' => is_array($value) ? array_reverse($value) : strrev(self::str($value)),
            'keys' => is_array($value) ? array_keys($value) : [],
            'values' => is_array($value) ? array_values($value) : [],
            'merge' => is_array($value) ? array_merge($value, array_map(fn ($a) => (array) $a, array_slice($args, 0))) : [],
            'slice' => is_array($value) ? array_slice($value, (int) ($args[0] ?? 0), isset($args[1]) ? (int) $args[1] : null) : [],
            'unique' => is_array($value) ? array_values(array_unique($value)) : [],
            'sum' => is_array($value) ? array_sum($value) : (float) $value,
            'sort' => is_array($value) ? self::sorted($value, (int) ($args[0] ?? SORT_REGULAR)) : $value,
            'quote' => '\'' . addslashes(self::str($value)) . '\'',
            'nl2p' => self::nl2p(self::str($value)),
            'fix' => $value,
            'html2text' => html_entity_decode(strip_tags(self::str($value)), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            // Fail soft: a modifier that slipped past the allow-list/compiler
            // must not take down the worker with an uncaught exception.  The
            // analyzer already refuses unknown modifiers at compile time.
            default => $value,
        };
    }

    private static function str(mixed $v): string
    {
        if (is_array($v)) {
            return '';
        }
        if ($v === null) {
            return '';
        }
        if (is_bool($v)) {
            return $v ? '1' : '';
        }
        if (is_object($v) && !method_exists($v, '__toString')) {
            return '';
        }
        return (string) $v;
    }

    private static function mb(string $fn, mixed $v): string
    {
        $s = self::str($v);
        return function_exists($fn) ? $fn($s, 'UTF-8') : (function_exists($fn) ? $fn($s) : ($fn === 'mb_strlen' ? (string) strlen($s) : $s));
    }

    private static function truncate(mixed $v, int $len, int $start = 0): string
    {
        $s = self::str($v);
        if ($start !== 0) {
            $s = mb_substr($s, $start);
        }
        if ($len <= 0) {
            return $s;
        }
        return mb_strlen($s, 'UTF-8') > $len ? mb_substr($s, 0, $len, 'UTF-8') : $s;
    }

    private static function date(string $fmt, mixed $ts): string
    {
        if (is_string($ts) && !preg_match('/^-?\d+$/', $ts)) {
            $ts = strtotime($ts);
        }
        return date($fmt, (int) ($ts ?: 0));
    }

    private static function nl2p(string $s): string
    {
        $parts = preg_split('/\n\s*\n/', $s) ?: [];
        return implode("\n", array_map(fn ($p) => '<p>' . nl2br($p) . '</p>', $parts));
    }

    /** @param array<mixed> $arr */
    private static function sorted(array $arr, int $flags): array
    {
        sort($arr, $flags);
        return $arr;
    }
}
