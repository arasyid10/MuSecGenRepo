<?php
declare(strict_types=1);

namespace App\Mutator\Support;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Name;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Scalar\String_;

final class PathPayloadConfig
{
    private const DEFAULT_CONFIG_PATHS = [
        'config/path-payloads.json',
        'path-payloads.json',
    ];

    /** @var null|array{name?:string,type:string,value?:string,const?:string,suffix?:string}[] */
    private static ?array $payloadSpecs = null;

    /** @var array<string,int[]> fungsi → indeks argumen untuk dimutasi */
    private static array $targetsArgIndexMap = [];

    /** @var string|null */
    private static ?string $constantBasepath = null;

    /** Muat konfigurasi sekali, cache di static. */
    public static function ensureLoaded(): void
    {
        if (self::$payloadSpecs !== null) {
            return;
        }

        $config = self::loadJson();
        self::$constantBasepath = isset($config['constant_basepath']) && is_string($config['constant_basepath'])
            ? $config['constant_basepath']
            : null;

        // targets: {"copy":[0,1], "rename":[0,1], ...}
        if (isset($config['targets']) && is_array($config['targets'])) {
            foreach ($config['targets'] as $fn => $idxs) {
                if (is_array($idxs)) {
                    self::$targetsArgIndexMap[strtolower((string)$fn)] =
                        array_values(array_filter($idxs, static fn($i) => is_int($i) && $i >= 0));
                }
            }
        }

        // payloads
        self::$payloadSpecs = [];
        if (isset($config['payloads']) && is_array($config['payloads'])) {
            foreach ($config['payloads'] as $p) {
                if (!is_array($p) || !isset($p['type'])) continue;
                $type = strtolower((string)$p['type']);
                if ($type === 'literal' && isset($p['value']) && is_string($p['value'])) {
                    self::$payloadSpecs[] = [
                        'name'  => (string)($p['name'] ?? 'literal'),
                        'type'  => 'literal',
                        'value' => $p['value'],
                    ];
                } elseif ($type === 'concat') {
                    $const = isset($p['const']) && is_string($p['const']) ? $p['const'] : (self::$constantBasepath ?? null);
                    $suffix = $p['suffix'] ?? null;
                    if (is_string($const) && is_string($suffix)) {
                        self::$payloadSpecs[] = [
                            'name'   => (string)($p['name'] ?? 'concat'),
                            'type'   => 'concat',
                            'const'  => $const,
                            'suffix' => $suffix,
                        ];
                    }
                }
            }
        }
    }

    /**
     * @return Expr[] Node expression siap pakai sebagai argumen path (String_ atau Concat(ConstFetch, String_))
     */
    public static function buildPayloadExprs(): array
    {
        self::ensureLoaded();

        $exprs = [];
        foreach (self::$payloadSpecs ?? [] as $p) {
            if ($p['type'] === 'literal' && isset($p['value'])) {
                $exprs[] = new String_((string)$p['value']);
            } elseif ($p['type'] === 'concat' && isset($p['const'], $p['suffix'])) {
                $exprs[] = new Concat(
                    new ConstFetch(new Name((string)$p['const'])),
                    new String_((string)$p['suffix'])
                );
            }
        }
        return $exprs;
    }

    /**
     * Ambil indeks argumen yang ingin dimutasi untuk fungsi tertentu.
     * Jika tidak di-set di config, defaultnya [0].
     *
     * @param string $functionName nama fungsi (lowercase)
     * @return int[]
     */
    public static function getArgIndexesForFunction(string $functionName): array
    {
        self::ensureLoaded();
        return self::$targetsArgIndexMap[$functionName] ?? [0];
    }

    /** @return array<string,mixed> */
    private static function loadJson(): array
    {
        $paths = self::DEFAULT_CONFIG_PATHS;
        // izinkan override via env
        $env = getenv('INFECTION_PATH_PAYLOADS');
        if (is_string($env) && $env !== '') {
            array_unshift($paths, $env);
        }

        foreach ($paths as $p) {
            $full = self::resolvePath($p);
            if ($full !== null && is_file($full)) {
                $raw = @file_get_contents($full);
                if ($raw !== false) {
                    $data = json_decode($raw, true);
                    if (is_array($data)) {
                        return $data;
                    }
                }
            }
        }
        // fallback: tanpa payload (mutator akan no-op)
        return [
            'payloads' => [],
        ];
    }

    /** Resolve relatif terhadap CWD. */
    private static function resolvePath(string $p): ?string
    {
        if ($p === '') return null;
        if ($p[0] === DIRECTORY_SEPARATOR || preg_match('/^[A-Za-z]:\\\\/', $p) === 1) {
            return $p; // absolut
        }
        $full = getcwd() . DIRECTORY_SEPARATOR . $p;
        return $full;
    }
}
