<?php
declare(strict_types=1);

namespace App\Mutator\Security;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\BinaryOp\NotIdentical;
use PhpParser\Node\Expr\BinaryOp\NotEqual;
use PhpParser\Node\Scalar\LNumber;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Node\Stmt\Nop;

/**
 * Menghapus guard berbasis hasil findPath()/strpos():
 *
 *   if (findPath($filePath) !== 0) { return false; }
 *   if (strpos($p, $base) != 0)     return false;
 *   if (0 !== findPath($p))         return false;
 *   if (false != strpos(...))       return false;
 *
 * Syarat:
 *  - If tanpa else/elseif
 *  - Body hanya: return false;
 *  - Kondisi adalah perbandingan "tidak sama" (!== atau !=)
 *    antara pemanggilan findPath()/strpos() dan 0/false (di kiri atau kanan).
 *
 * Mutasi: ganti seluruh If dengan NOP (dihilangkan).
 */
final class ExFindPathCheckingMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof If_) {
            return false;
        }

        // Hanya If tanpa else/elseif
        if ($node->else !== null || !empty($node->elseifs)) {
            return false;
        }

        // Body harus tepat satu: return false;
        if (\count($node->stmts) !== 1 || !$node->stmts[0] instanceof Return_) {
            return false;
        }
        if (!$this->isReturnFalse($node->stmts[0])) {
            return false;
        }

        // Kondisi: NotIdentical atau NotEqual
        $cond = $node->cond;
        if (!($cond instanceof NotIdentical || $cond instanceof NotEqual)) {
            return false;
        }

        // Salah satu sisi adalah funcCall findPath()/strpos(), sisi lain 0 atau false
        return $this->isFindPathOrStrposVsZeroFalse($cond);
    }

    public function mutate(Node $node): iterable
    {
        // Hapus seluruh if (jadikan NOP)
        yield new Nop($node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Removes findPath/strpos guard: `if (findPath(...) !== 0) { return false; }`.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- if (findPath($filePath) !== 0) {
-     return false;
- }
+ // guard removed
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* ===== Helpers ===== */

    private function isReturnFalse(Return_ $ret): bool
    {
        if (!$ret->expr instanceof ConstFetch) {
            return false;
        }
        return strtolower($ret->expr->name->toString()) === 'false';
    }

    private function isFindPathOrStrposVsZeroFalse(NotIdentical|NotEqual $bin): bool
    {
        [$left, $right] = [$bin->left, $bin->right];

        // pola A: funcCall <op> (0|false)
        if ($this->isFindPathOrStrposCall($left) && $this->isZeroOrFalse($right)) {
            return true;
        }
        // pola B: (0|false) <op> funcCall
        if ($this->isZeroOrFalse($left) && $this->isFindPathOrStrposCall($right)) {
            return true;
        }
        return false;
    }

    private function isFindPathOrStrposCall(Expr $expr): bool
    {
        if (!$expr instanceof FuncCall) {
            return false;
        }
        $resolved = $expr->getAttribute('resolvedName');
        $fn = $resolved instanceof Name
            ? strtolower($resolved->toString())
            : ($expr->name instanceof Name ? strtolower($expr->name->toString()) : null);

        return $fn === 'findpath' || $fn === '\findpath' || $fn === 'strpos' || $fn === '\strpos';
    }

    private function isZeroOrFalse(Expr $expr): bool
    {
        if ($expr instanceof LNumber) {
            return $expr->value === 0;
        }
        if ($expr instanceof ConstFetch) {
            return strtolower($expr->name->toString()) === 'false';
        }
        return false;
    }
}
