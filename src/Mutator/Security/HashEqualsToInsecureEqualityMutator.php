<?php
declare(strict_types=1);

namespace App\Mutator\Security;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Name;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\BinaryOp\Identical;
use PhpParser\Node\Expr\BinaryOp\Equal;
use PhpParser\Node\Scalar\String_;

/**
 * Mutates: hash_equals($expected, $submitted) →
 *   1) $expected === $submitted
 *   2) $expected ==  $submitted
 *   3) strcmp($expected, $submitted)
 *   4) strcasecmp($expected, $submitted)
 *   5) strcoll($expected, $submitted)
 *   6) levenshtein($expected, $submitted)
 *
 * - Menangani hash_equals() maupun \hash_equals() (via resolvedName).
 * - Wajib 2 argumen.
 * - Menghasilkan 6 mutan.
 */
final class HashEqualsToInsecureEqualityMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) {
            return false;
        }

        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name
            ? strtolower($resolved->toString())
            : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);

        return $fn === 'hash_equals' && \count($node->args) >= 2;
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        // Ambil dua argumen (ekspresi murni, bukan Arg)
        $a = $node->args[0]->value;
        $b = $node->args[1]->value;

        // 1) ===
        yield new Identical($a, $b, $node->getAttributes());

        // 2) ==
        yield new Equal($a, $b, $node->getAttributes());

        // 3) strcmp($a, $b)
        yield new FuncCall(new Name('strcmp'), [new Arg($a), new Arg($b)], $node->getAttributes());

        // 4) strcasecmp($a, $b)
        yield new FuncCall(new Name('strcasecmp'), [new Arg($a), new Arg($b)], $node->getAttributes());

        // 5) strcoll($a, $b)
        yield new FuncCall(new Name('strcoll'), [new Arg($a), new Arg($b)], $node->getAttributes());

        // 6) levenshtein($a, $b)
        yield new FuncCall(new Name('levenshtein'), [new Arg($a), new Arg($b)], $node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces hash_equals($expected, $submitted) with insecure/incorrect equality/compare alternatives.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- return hash_equals($expected, $submittedToken);
+ return $expected === $submittedToken;
// atau salah satu alternatif lain (==, strcmp, strcasecmp, strcoll, levenshtein)
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
