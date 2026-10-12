<?php
declare(strict_types=1);

namespace App\Mutator;

use App\Mutator\Support\PathPayloadConfig;
use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;

final class PathPayloadOperatorFuncCallMutator implements Mutator
{
    /** Fungsi target yang lazim menerima path sebagai argumen pertama. */
    private const TARGETS = [
        'file_get_contents',
        'file_put_contents',
        'fopen',
        'readfile',
        'file',
        'unlink',
        'copy',
        'rename',
        'realpath',
        'file_exists',
        'is_file',
        'is_dir',
        'scandir',
        'opendir',
        'mkdir',
        'rmdir',
        'chdir',
        'chmod',
        'chown',
        'lchown',
        'symlink',
        'link',
        'touch',
    ];

    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) {
            return false;
        }

        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name ? strtolower($resolved->toString())
             : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);

        if ($fn === null) return false;
        if (!\in_array($fn, self::TARGETS, true)) return false;
        if (\count($node->args) === 0) return false;

        // Pastikan ada payload yang bisa dipakai
        return \count(PathPayloadConfig::buildPayloadExprs()) > 0;
    }

    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name ? strtolower($resolved->toString())
             : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);
        if ($fn === null) {
            return; // no-op
        }

        $payloads = PathPayloadConfig::buildPayloadExprs();
        if (!$payloads) {
            return; // no payloads configured
        }

        // Tentukan indeks argumen yang dimutasi untuk fungsi ini (default [0])
        $argIndexes = PathPayloadConfig::getArgIndexesForFunction($fn);

        foreach ($payloads as $payloadExpr) {
            // Untuk setiap payload, kita juga hasilkan mutan untuk setiap arg index yang dipilih
            foreach ($argIndexes as $idx) {
                if (!isset($node->args[$idx])) {
                    continue;
                }
                $args = $node->args;
                $args[$idx] = new \PhpParser\Node\Arg($payloadExpr);
                yield new FuncCall($node->name, $args, $node->getAttributes());
            }
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            <<<'TXT'
Path Payload Operator (FuncCall): replaces a path argument of common filesystem functions with payloads
defined in config/path-payloads.json, such as an in-project file or outside/unauthorized traversal payloads.
TXT,
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- $c = file_get_contents($path);
+ $c = file_get_contents("C:\\xampp\\htdocs\\samplecode\\MyProject\\File.txt"); // from config
// or
+ $c = file_get_contents(\App\basepath . "\\..\\..\\..\\config.ini");          // from config
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
