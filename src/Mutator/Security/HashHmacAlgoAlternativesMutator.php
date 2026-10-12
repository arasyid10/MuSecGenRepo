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
 * Mutates: hash_hmac($algo, $data, $key[, $binary]) → hash_hmac("<ALT>", $data, $key[, $binary])
 * ALT ∈ {"Md5","SHA-1","SHA-256","SHA-512","Whirlpool","RIPEMD-160"}.
 *
 * - Bekerja untuk \hash_hmac() maupun hash_hmac() (resolvedName).
 * - Mensyaratkan ≥ 3 argumen (algo, data, key).
 * - Menghasilkan 6 mutan (satu per algoritma).
 */
final class HashHmacAlgoAlternativesMutator implements Mutator
{
    /** @var string[] */
    private const ALT_ALGOS = ['md5', 'SHA-1', 'SHA-256', 'SHA-512', 'Whirlpool', 'RIPEMD-160'];

    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) {
            return false;
        }

        // Dapatkan nama fungsi yang sudah di-resolve (global) atau dari name.
        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name ? strtolower($resolved->toString())
             : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);

        // Minimal 3 argumen: algo, data, key
        return $fn === 'hash_hmac' && \count($node->args) >= 3;
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        foreach (self::ALT_ALGOS as $algo) {
            $args = $node->args;
            // ganti argumen pertama (algo) menjadi string literal
            $args[0] = new Arg(new String_($algo));
            yield new FuncCall($node->name, $args, $node->getAttributes());
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces the $algo argument of hash_hmac() with one of {Md5,SHA-1,SHA-256,SHA-512,Whirlpool,RIPEMD-160}.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- $mac = hash_hmac($this->hashAlgo, $message, $key);
+ $mac = hash_hmac("SHA-1", $message, $key);
DIFF
        );
    }
    public function getName(): string
    {
        return self::class;
    }
}
