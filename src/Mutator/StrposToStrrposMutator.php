<?php
declare(strict_types=1);

namespace App\Mutator;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;

final class StrposToStrrposMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) return false;

        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name ? strtolower($resolved->toString())
             : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);

        return $fn === 'strpos' && \count($node->args) >= 2;
    }

    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        yield new FuncCall(new Name('strrpos'), $node->args, $node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces strpos($h, $n[, $o]) with strrpos($h, $n[, $o]).',
            MutatorCategory::ORTHOGONAL_REPLACEMENT,
            null,
            <<<'DIFF'
- $p = strpos($h, $n);
+ $p = strrpos($h, $n);
DIFF
        );
    }

    public function getName(): string { return self::class; }
}
