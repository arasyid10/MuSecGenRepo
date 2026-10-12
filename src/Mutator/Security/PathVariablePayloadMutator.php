<?php
declare(strict_types=1);

namespace App\Mutator\Security;

use App\Mutator\Support\PathPayloadConfig2;
use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\String_;

/**
 * Mutates assignments to $Spath or $filePath:
 *
 *   $Spath = <expr>;     → $Spath = "<PAYLOAD>";
 *   $filePath = <expr>;  → $filePath = "<PAYLOAD>";
 *
 * (Juga mendukung $this->Spath / $this->filePath)
 *
 * Payload diambil dari config (env INFECTION_PATH_PAYLOADS atau config/path-payloads.json)
 * dengan fallback default. Tiap payload → satu mutan.
 */
final class PathVariablePayloadMutator implements Mutator
{
    /** @var string[] variable/property names yang ditarget */
    private const TARGET_NAMES = ['Spath', 'filePath'];

    public function canMutate(Node $node): bool
    {
        if (!$node instanceof Assign) {
            return false;
        }
        return $this->isTargetLhs($node->var);
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        \assert($node instanceof Assign);

        $payloads = PathPayloadConfig2::getPayloads();

        foreach ($payloads as $p) {
            yield new Assign(
                $node->var,
                new String_($p),
                $node->getAttributes()
            );
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces the RHS of assignments to $Spath/$filePath with curated path payloads (inside/outside, traversal, encoded, mixed separators).',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- $filePath = sanitize($_GET['p']);
+ $filePath = "D:\\Kegiatanku\\...\\config\\path-payloads.json";
# atau
+ $filePath = "D:\\Kegiatanku\\...\\tests\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt";
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* ===== helpers ===== */

    private function isTargetLhs(Expr $expr): bool
    {
        // $Spath / $filePath
        if ($expr instanceof Variable && is_string($expr->name)) {
            return \in_array($expr->name, self::TARGET_NAMES, true);
        }

        // $this->Spath / $this->filePath
        if ($expr instanceof PropertyFetch && $expr->name instanceof Identifier) {
            return \in_array($expr->name->toString(), self::TARGET_NAMES, true);
        }

        return false;
    }
}
