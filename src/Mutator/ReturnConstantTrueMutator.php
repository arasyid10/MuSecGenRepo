<?php
declare(strict_types=1);

namespace App\Mutator;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Stmt\Return_;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Expr\ConstFetch;

final class ReturnConstantTrueMutator implements Mutator
{
    private const TARGETS = [
        'strpos','stripos','str_contains','str_starts_with','str_ends_with','strrpos','strstr','strpbrk',
    ];

    public function canMutate(Node $node): bool
    {
        if (!$node instanceof Return_) return false;
        $expr = $node->expr;
        if (!$expr instanceof FuncCall) return false;

        $resolved = $expr->getAttribute('resolvedName');
        $fn = $resolved instanceof Name ? strtolower($resolved->toString())
             : ($expr->name instanceof Name ? strtolower($expr->name->toString()) : null);

        return $fn !== null && \in_array($fn, self::TARGETS, true);
    }

    public function mutate(Node $node): iterable
    {
        \assert($node instanceof Return_);

        yield new Return_(new ConstFetch(new Name('true')), $node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces return of a path-related string function call with return true;',
            MutatorCategory::ORTHOGONAL_REPLACEMENT,
            null,
            <<<'DIFF'
- return strpos($p, $base) !== false;
+ return true;
DIFF
        );
    }

    public function getName(): string { return self::class; }
}
