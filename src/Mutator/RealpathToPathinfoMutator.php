<?php

declare(strict_types=1);

namespace App\Mutator;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Name;

/**
 * Mengganti pemanggilan fungsi global:
 *   realpath($x)  ->  pathinfo($x, PATHINFO_DIRNAME)
 */
final class RealpathToPathinfoMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) {
            return false;
        }

        // Ambil nama fungsi yang sudah di-resolve (jika ada)
        $resolved = $node->getAttribute('resolvedName'); // FullyQualified|Name|null

        $fn = null;
        if ($resolved instanceof Name) {
            $fn = strtolower(ltrim($resolved->toString(), '\\'));
        } elseif ($node->name instanceof Name) {
            // fallback jika belum di-resolve
            $fn = strtolower(ltrim($node->name->toString(), '\\'));
        }

        if ($fn !== 'realpath') {
            return false;
        }

        // Pastikan sesuai signature umum realpath($path)
        return \count($node->args) === 1;
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        $newCall = new FuncCall(
            new Name('pathinfo'),
            [
                // Gunakan argumen asli sebagai argumen pertama
                $node->args[0],
                // Tambahkan flag kedua: PATHINFO_DIRNAME agar hasilnya string dirname (bukan array)
                new Node\Arg(new ConstFetch(new Name('PATHINFO_DIRNAME'))),
            ],
            $node->getAttributes() // pertahankan atribut AST (komentar/posisi)
        );

        yield $newCall;
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            <<<'TXT'
Replaces global function call realpath($arg) with pathinfo($arg, PATHINFO_DIRNAME).
TXT,
            MutatorCategory::ORTHOGONAL_REPLACEMENT,
            null,
            <<<'DIFF'
- $p = realpath($x);
+ $p = pathinfo($x, PATHINFO_DIRNAME);
DIFF
        );
    }

    public function getName(): string
    {
        // Nama yang akan Anda cantumkan di infection.json / infection.json5
        return self::class;
    }
}
