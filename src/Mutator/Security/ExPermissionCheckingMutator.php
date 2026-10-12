<?php
declare(strict_types=1);

namespace App\Mutator\Security;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\BooleanNot;
use PhpParser\Node\Expr\BinaryOp\Equal;
use PhpParser\Node\Expr\BinaryOp\Identical;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Node\Stmt\Nop;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;

/**
 * Menghapus guard permission:
 *
 *  if (!userHasPermission(...)) { return false; }
 *  if (userHasPermission(...) === false) { return false; }
 *  if (false === userHasPermission(...)) { return false; }
 *
 * Juga mendukung pemanggilan method: $acl->hasPermission(...), Acl::isAuthorized(...).
 * Mutasi: seluruh If_ diganti NOP.
 */
final class ExPermissionCheckingMutator implements Mutator
{
    /** daftar nama fungsi/metode yang diperlakukan sebagai pengecekan permission */
    private const PERM_NAMES = [
        'userhaspermission', 'haspermission', 'canaccess',
        'isauthorized', 'isauthorised', 'ispermited', 'ispermitted',
        'authorize', 'authorise', 'checkpermission', 'checkpermissions',
    ];

    public function canMutate(Node $node): bool
    {
        if (!$node instanceof If_) {
            return false;
        }

        // Tidak ada else/elseif
        if ($node->else !== null || !empty($node->elseifs)) {
            return false;
        }

        // Body tepat satu: return false;
        if (\count($node->stmts) !== 1 || !$node->stmts[0] instanceof Return_) {
            return false;
        }
        if (!$this->isReturnFalse($node->stmts[0])) {
            return false;
        }

        // Pola kondisi yang didukung:
        // 1) if (! <permCall>(...))
        $cond = $node->cond;
        if ($cond instanceof BooleanNot && $this->isPermissionCall($cond->expr)) {
            return true;
        }

        // 2) if (<permCall>(...) === false)   / if (<permCall>(...) == false)
        if (($cond instanceof Identical || $cond instanceof Equal)
            && $this->isPermissionCall($cond->left)
            && $this->isFalseConst($cond->right)) {
            return true;
        }

        // 3) if (false === <permCall>(...))   / if (false == <permCall>(...))
        if (($cond instanceof Identical || $cond instanceof Equal)
            && $this->isFalseConst($cond->left)
            && $this->isPermissionCall($cond->right)) {
            return true;
        }

        return false;
    }

    public function mutate(Node $node): iterable
    {
        // Hilangkan seluruh if-guard
        yield new Nop($node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Removes permission guard: `if (!userHasPermission(...)) { return false; }`.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- if (!userHasPermission($userId, !$normalizedPath, $pdo)) {
-     return false;
- }
+ // permission guard removed
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* ---------- helpers ---------- */

    private function isReturnFalse(Return_ $ret): bool
    {
        return $ret->expr instanceof ConstFetch
            && strtolower($ret->expr->name->toString()) === 'false';
    }

    private function isFalseConst(Expr $expr): bool
    {
        return $expr instanceof ConstFetch
            && strtolower($expr->name->toString()) === 'false';
    }

    /** apakah expr adalah pemanggilan permission check (func/method/static) */
    private function isPermissionCall(Expr $expr): bool
    {
        // Fungsi global
        if ($expr instanceof FuncCall) {
            $resolved = $expr->getAttribute('resolvedName');
            $fn = $resolved instanceof Name
                ? strtolower($resolved->toString())
                : ($expr->name instanceof Name ? strtolower($expr->name->toString()) : null);

            if ($fn !== null) {
                $fn = ltrim($fn, '\\');
                return \in_array($fn, self::PERM_NAMES, true);
            }
        }

        // Method call: $obj->hasPermission(...)
        if ($expr instanceof MethodCall && $expr->name instanceof Identifier) {
            $m = strtolower($expr->name->toString());
            return \in_array($m, self::PERM_NAMES, true);
        }

        // Static call: Acl::isAuthorized(...)
        if ($expr instanceof StaticCall && $expr->name instanceof Identifier) {
            $m = strtolower($expr->name->toString());
            return \in_array($m, self::PERM_NAMES, true);
        }

        return false;
    }
}