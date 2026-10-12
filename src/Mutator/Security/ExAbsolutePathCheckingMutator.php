<?php
declare(strict_types=1);

namespace App\Mutator\Security;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\If_;
use PhpParser\Node\Stmt\Nop;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Node\Expr\BooleanNot;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ConstFetch;

final class ExAbsolutePathCheckingMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof If_) return false;

        if ($node->else !== null || !empty($node->elseifs)) return false;

        if (count($node->stmts) !== 1 || !$node->stmts[0] instanceof Return_) return false;

        /** @var Return_ $ret */
        $ret = $node->stmts[0];
        if (!$this->isReturnFalse($ret)) return false;

        if (!$node->cond instanceof BooleanNot) return false;

        return $this->isPathVarOrAbsCall($node->cond->expr);
    }

    public function mutate(Node $node): iterable
    {
        yield new Nop($node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Removes absolute-path guard: `if (!$normalizedPath) { return false; }`.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- if (!$normalizedPath) {
-     return false;
- }
+ // guard removed
DIFF
        );
    }

    public function getName(): string { return self::class; }

    private function isReturnFalse(Return_ $ret): bool
    {
        if (!$ret->expr instanceof ConstFetch) return false;
        $name = strtolower($ret->expr->name->toString());
        return $name === 'false';
    }

    private function isPathVarOrAbsCall(Expr $expr): bool
    {
        if ($expr instanceof Variable) {
            if (is_string($expr->name)) {
                return (bool) preg_match('/path/i', $expr->name);
            }
            return true;
        }

        if ($expr instanceof FuncCall) {
            $resolved = $expr->getAttribute('resolvedName');
            $fn = $resolved instanceof Name
                ? strtolower($resolved->toString())
                : ($expr->name instanceof Name ? strtolower($expr->name->toString()) : null);

            return $fn === 'abspath' || $fn === '\abspath' || $fn === 'realpath' || $fn === '\realpath';
        }

        return false;
    }
}
