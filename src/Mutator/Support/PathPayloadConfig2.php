<?php
declare(strict_types=1);

namespace App\Mutator\Support;

final class PathPayloadConfig2
{
    /**
     * Public API: kembalikan daftar payload (string), unik & dibatasi limit.
     * Mendukung:
     * - Format lama: { "payloads": ["C:\\...", "..\\..\\config.ini", ...] }
     * - Format baru (terstruktur): lihat contoh JSON di pertanyaan.
     */
    public static function getPayloads(int $limit = 16): array
    {
        $cfg = self::loadJson();
        $limit = max(1, min(64, (int)($cfg['limit'] ?? $limit)));

        $payloads = [];

        if (isset($cfg['payloads'])) {
            // 1) Coba parse format baru (array of objects dgn type)
            $structured = self::parseStructuredPayloads($cfg);
            if ($structured) {
                $payloads = $structured;
            } else {
                // 2) Fallback: format lama (array of strings / nested)
                $payloads = self::normalizeList($cfg['payloads']);
            }
        }

        if (!$payloads) {
            $payloads = self::defaults();
        }

        // unique, reindex, slice by limit
        $payloads = array_values(array_unique(array_filter($payloads, static fn($s) => is_string($s) && $s !== '')));
        return array_slice($payloads, 0, $limit);
    }

    /** ----------------------- internal helpers ----------------------- */

    /** Load JSON dari ENV atau file default. */
    private static function loadJson(): array
    {
        $paths = [];
        // ENV menunjuk ke FILE JSON (bukan folder)
        $env = getenv('INFECTION_PATH_PAYLOADS');
        if (is_string($env) && $env !== '') {
            $paths[] = $env;
        }
        $paths[] = getcwd() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'path-payloads.json';

        foreach ($paths as $p) {
            if (is_file($p)) {
                $raw = @file_get_contents($p);
                if ($raw !== false) {
                    $d = json_decode($raw, true);
                    if (is_array($d)) {
                        return $d;
                    }
                }
            }
        }
        return [];
    }

    /** Normalisasi list lama (bisa nested) → array of string */
    private static function normalizeList(mixed $v): array
    {
        $out = [];
        $walk = function ($x) use (&$out, &$walk) {
            if (is_array($x)) {
                foreach ($x as $e) { $walk($e); }
            } elseif (is_string($x)) {
                $s = trim($x);
                if ($s !== '') { $out[] = $s; }
            }
        };
        $walk($v);
        return $out;
    }

    /**
     * Parse format terstruktur:
     * {
     *   "config_version": 1,
     *   "constant_basepath": "\\App\\basepath",
     *   "basepath_value": "D:\\path\\to\\base"     (opsional)
     *   "payloads": [
     *     { "name":"inside_literal", "type":"literal", "value":"C:\\...\\File.txt" },
     *     { "name":"outside_config", "type":"concat", "const":"\\App\\basepath", "suffix":"\\..\\..\\..\\config.ini" },
     *     ...
     *   ]
     * }
     */
    private static function parseStructuredPayloads(array $cfg): array
    {
        if (!isset($cfg['payloads']) || !is_array($cfg['payloads'])) {
            return [];
        }

        $result = [];

        // Resolve basepath global (prioritas: ENV → basepath_value → konstanta FQN → null)
        $globalConstRef = isset($cfg['constant_basepath']) && is_string($cfg['constant_basepath'])
            ? $cfg['constant_basepath'] : null;

        $basepathValueOverride = isset($cfg['basepath_value']) && is_string($cfg['basepath_value'])
            ? $cfg['basepath_value'] : null;

        $globalBase = self::resolveBasepath($globalConstRef, $basepathValueOverride);

        foreach ($cfg['payloads'] as $item) {
            if (!is_array($item) || !isset($item['type'])) {
                continue;
            }

            $type = strtolower((string)$item['type']);

            if ($type === 'literal') {
                $val = isset($item['value']) ? (string)$item['value'] : '';
                if ($val !== '') {
                    $result[] = $val;
                }
                continue;
            }

            if ($type === 'concat') {
                $constRef = isset($item['const']) && is_string($item['const']) ? $item['const'] : $globalConstRef;
                $suffix   = isset($item['suffix']) ? (string)$item['suffix'] : '';

                // Resolusi base utk payload ini: ENV/basepath_value/konstanta/item
                $base = self::resolveBasepath($constRef, $basepathValueOverride);
                if ($base === null) {
                    // fallback terakhir: kalau tidak bisa resolve, pakai cwd supaya string tetap konkrit
                    $base = getcwd();
                }

                $result[] = self::concatRaw($base, $suffix);
                continue;
            }

            // tipe lain diabaikan (tidak error)
        }

        return $result;
    }

    /**
     * Resolve basepath:
     * 1) ENV INFECTION_BASEPATH
     * 2) override dari JSON: basepath_value
     * 3) konstanta FQN (mis. "\App\basepath") jika terdefinisi
     * 4) null
     */
    private static function resolveBasepath(?string $constRef, ?string $overrideValue): ?string
    {
        $env = getenv('INFECTION_BASEPATH');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        if (is_string($overrideValue) && $overrideValue !== '') {
            return $overrideValue;
        }
        if (is_string($constRef) && $constRef !== '') {
            $c1 = $constRef;
            $c2 = ltrim($constRef, '\\');
            if (\defined($c1)) { return (string)\constant($c1); }
            if (\defined($c2)) { return (string)\constant($c2); }
        }
        return null;
    }

    /** Gabung base + suffix apa adanya (tanpa normalisasi agresif) */
    private static function concatRaw(string $base, string $suffix): string
    {
        // Jika suffix sudah diawali separator, langsung tempel
        if ($suffix === '') {
            return $base;
        }
        // Hindari duplikasi backslash pada boundary
        if (($base !== '') && ($suffix !== '') &&
            (str_ends_with($base, '\\') || str_ends_with($base, '/')) &&
            ($suffix[0] === '\\' || $suffix[0] === '/')) {
            return $base . substr($suffix, 1);
        }
        return $base . $suffix;
    }

    /** Default fallback bila JSON kosong */
    private static function defaults(): array
    {
        return [
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            '..\\..\\..\\..\\config.ini',
            '%2e%2e\\%2e%2e\\secret.txt',
            'C:\\temp\\..\\..\\forbidden.txt',
            '/etc/passwd',
        ];
    }
}
