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
use PhpParser\Node\Scalar\String_;

final class ReplaceSecondArgWithDriveMutator implements Mutator
{
    /** Fungsi string terkait path (argumen ke-2 = needle/basepath) */
    private const TARGETS = [
        'strpos', 'stripos', 'str_contains', 'str_starts_with', 'str_ends_with', 'strrpos', 'strstr', 'strpbrk',
    ];

    /** Drives yang akan dicoba sebagai pengganti argumen ke-2 */
    private const DRIVES = ['C:\\', 'D:\\'];

    public function canMutate(Node $node): bool
    {
        if (!$node instanceof FuncCall) {
            return false;
        }

        $resolved = $node->getAttribute('resolvedName');
        $fn = $resolved instanceof Name
            ? strtolower($resolved->toString())
            : ($node->name instanceof Name ? strtolower($node->name->toString()) : null);

        return $fn !== null
            && \in_array($fn, self::TARGETS, true)
            && \count($node->args) >= 2;
    }

    public function mutate(Node $node): iterable
    {
        \assert($node instanceof FuncCall);

        foreach (self::DRIVES as $drive) {
            $args = $node->args;                 // salin argumen asli
            $args[1] = new Arg(new String_($drive)); // ganti argumen ke-2 (needle/basepath)
            yield new FuncCall($node->name, $args, $node->getAttributes());
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces the 2nd argument of path-related string functions with Windows drive roots (e.g., "C:\\", "D:\\").',
            MutatorCategory::ORTHOGONAL_REPLACEMENT,
            null,
            <<<'DIFF'
- strpos($p, $base)
+ strpos($p, "C:\\")
+ strpos($p, "D:\\")
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
