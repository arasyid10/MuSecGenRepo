<?php

declare(strict_types=1);

namespace App\Mutator;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;

/**
 * Mengganti pemanggilan fungsi global realpath($x) -> basename($x)
 */
final class RealpathToBasenameMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) {
            return false;
        }

        // Dapatkan nama fungsi yang sudah di-resolve (jika tersedia)
        $resolved = $node->getAttribute('resolvedName'); // FullyQualified|Name|null

        $fn = null;
        if ($resolved instanceof Name) {
            $fn = strtolower($resolved->toString()); // contoh: 'realpath'
        } elseif ($node->name instanceof Name) {
            // fallback jika belum di-resolve
            $fn = strtolower($node->name->toString());
        }

        if ($fn !== 'realpath') {
            return false;
        }

        // Batasi ke 1 argumen agar sesuai signature umum realpath
        return \count($node->args) === 1;
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        $newCall = new FuncCall(
            new Name('basename'),
            $node->args,                   // gunakan argumen yang sama
            $node->getAttributes()         // pertahankan atribut AST
        );

        yield $newCall;
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            <<<'TXT'
Replaces global function call realpath($arg) with basename($arg).
TXT,
            MutatorCategory::ORTHOGONAL_REPLACEMENT,
            null,
            <<<'DIFF'
- $p = realpath($x);
+ $p = basename($x);
DIFF
        );
    }

    public function getName(): string
    {
        // Nama yang akan Anda cantumkan di infection.json5
        return self::class;
    }
}
