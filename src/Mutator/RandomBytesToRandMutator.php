<?php
declare(strict_types=1);

namespace App\Mutator;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Arg;
use PhpParser\Node\Scalar\LNumber;

final class RandomBytesToRandMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) return false;

        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name ? strtolower($resolved->toString())
             : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);

        return $fn === 'random_bytes' && \count($node->args) === 1;
    }

    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        $args = [
            new Arg(new LNumber(0)),  // min
            $node->args[0],           // max = $len
        ];

        yield new FuncCall(new Name('rand'), $args, $node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces random_bytes($len) with rand(0, $len). (string → int, non-crypto)',
            MutatorCategory::ORTHOGONAL_REPLACEMENT,
            null,
            <<<'DIFF'
- $t = random_bytes($len);
+ $t = rand(0, $len);
DIFF
        );
    }

    public function getName(): string { return self::class; }
}
