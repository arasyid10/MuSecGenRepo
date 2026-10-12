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

/**
 * Mutates: strcmp($expected, $submitted)
 *   → ($expected === $submitted)
 *   → ($expected ==  $submitted)
 *   → hash_equals($expected, $submitted)
 *   → strcasecmp($expected, $submitted)
 *   → strcoll($expected, $submitted)
 *   → levenshtein($expected, $submitted)
 *
 * - Menangani strcmp() dan \strcmp() (via resolvedName).
 * - Minimal 2 argumen.
 * - Menghasilkan 6 mutan.
 */
final class StrcmpToEqualityAlternativesMutator implements Mutator
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

        return $fn === 'strcmp' && \count($node->args) >= 2;
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        $a = $node->args[0]->value;
        $b = $node->args[1]->value;

        // 1) ===
        yield new Identical($a, $b, $node->getAttributes());

        // 2) ==
        yield new Equal($a, $b, $node->getAttributes());

        // 3) hash_equals($a, $b)
        yield new FuncCall(new Name('hash_equals'), [new Arg($a), new Arg($b)], $node->getAttributes());

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
            'Replaces strcmp($expected, $submitted) with equality/security/string-compare alternatives (===, ==, hash_equals, strcasecmp, strcoll, levenshtein).',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- return strcmp($expected, $submittedToken);
+ return $expected === $submittedToken;
// atau salah satu alternatif lain (==, hash_equals, strcasecmp, strcoll, levenshtein)
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
