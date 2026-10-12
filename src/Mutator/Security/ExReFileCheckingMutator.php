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
use PhpParser\Node\Expr\BinaryOp\BooleanAnd;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Node\Expr\ConstFetch;

/**
 * Menghapus guard:
 *
 * if (file_exists($x) && is_readable($x)) {
 *     return true;
 * } else {
 *     return false;
 * }
 * menjadi:
 * return true;
 *
 * Syarat:
 *  - If_ memiliki ELSE (tanpa elseif)
 *  - THEN: return true;  dan  ELSE: return false;
 *  - Kondisi adalah BooleanAnd dari file_exists() & is_readable() (urutan bebas)
 */
final class ExReFileCheckingMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof If_) {
            return false;
        }

        // Harus ada ELSE & tidak ada ELSEIF
        if ($node->else === null || !empty($node->elseifs)) {
            return false;
        }

        // THEN hanya "return true;"
        if (\count($node->stmts) !== 1 || !$node->stmts[0] instanceof Return_) {
            return false;
        }
        if (!$this->isReturnBool($node->stmts[0], true)) {
            return false;
        }

        // ELSE hanya "return false;"
        if (\count($node->else->stmts) !== 1 || !$node->else->stmts[0] instanceof Return_) {
            return false;
        }
        if (!$this->isReturnBool($node->else->stmts[0], false)) {
            return false;
        }

        // Kondisi harus "file_exists(...) && is_readable(...)" (urutan bebas)
        return $this->isExistsAndReadableAnd($node->cond);
    }

    public function mutate(Node $node): iterable
    {
        // Ganti seluruh If_ menjadi "return true;"
        $retTrue = new Return_(new ConstFetch(new Name('true')), $node->getAttributes());
        yield $retTrue;
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces a file-existence/readability guard `if (file_exists(...) && is_readable(...)) { return true; } else { return false; }` with `return true;`.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- if (file_exists($normalizedPath) && is_readable($normalizedPath)) {
-     return true;
- } else {
-     return false;
- }
+ return true;
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* ========== helpers ========== */

    private function isReturnBool(Return_ $ret, bool $expected): bool
    {
        if (!$ret->expr instanceof ConstFetch) {
            return false;
        }
        $name = strtolower($ret->expr->name->toString());
        return $expected ? $name === 'true' : $name === 'false';
    }

    private function isExistsAndReadableAnd(Expr $cond): bool
    {
        if (!$cond instanceof BooleanAnd) {
            return false;
        }
        return ($this->isFunc($cond->left, ['file_exists']) && $this->isFunc($cond->right, ['is_readable']))
            || ($this->isFunc($cond->left, ['is_readable']) && $this->isFunc($cond->right, ['file_exists']));
    }

    private function isFunc(Expr $expr, array $names): bool
    {
        if (!$expr instanceof FuncCall) {
            return false;
        }
        $resolved = $expr->getAttribute('resolvedName');
        $fn = $resolved instanceof Name
            ? strtolower($resolved->toString())
            : ($expr->name instanceof Name ? strtolower($expr->name->toString()) : null);

        if ($fn === null) {
            return false;
        }
        $fn = ltrim($fn, '\\');
        foreach ($names as $n) {
            if ($fn === strtolower($n)) {
                return true;
            }
        }
        return false;
    }
}
