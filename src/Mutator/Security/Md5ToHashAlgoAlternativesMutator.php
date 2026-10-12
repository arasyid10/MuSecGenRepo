<?php
declare(strict_types=1);

namespace App\Mutator\Security;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;

/**
 * Mutates:
 *   md5($data)
 * into:
 *   hash("<ALT>", $data)
 *
 * ALT ∈ {"sha1","sha256","sha512","whirlpool","ripemd160"}
 *
 * - Bekerja untuk \md5() maupun md5() (resolvedName).
 * - Mensyaratkan minimal 1 argumen.
 * - Menghasilkan 5 mutan.
 */
final class Md5ToHashAlgoAlternativesMutator implements Mutator
{
    /** @var string[] */
    private const ALT_ALGOS = ['sha1', 'sha256', 'sha512', 'whirlpool', 'ripemd160'];

    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) {
            return false;
        }

        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name ? strtolower($resolved->toString())
            : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);

        return $fn === 'md5' && \count($node->args) >= 1;
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        // ambil argumen md5($data)
        $dataArg = $node->args[0];

        foreach (self::ALT_ALGOS as $algo) {
            yield new FuncCall(
                new Name('hash'),
                [
                    new Arg(new String_($algo)),
                    $dataArg,
                ],
                $node->getAttributes()
            );
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces md5($data) with hash("<ALT>", $data) where ALT ∈ {sha1,sha256,sha512,whirlpool,ripemd160}.',
            MutatorCategory::ORTHOGONAL_REPLACEMENT,
            null,
            <<<'DIFF'
- $token = md5(uniqid());
+ $token = hash("sha256", uniqid());
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
