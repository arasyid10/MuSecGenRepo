<?php
declare(strict_types=1);

namespace App\Mutator;

use App\Mutator\Support\PathPayloadConfig;
use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Expr\Include_;

final class PathPayloadOperatorIncludeMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if (!$node instanceof Include_) return false;
        // Pastikan ada payload
        return \count(PathPayloadConfig::buildPayloadExprs()) > 0;
    }

    public function mutate(Node $node): iterable
    {
        \assert($node instanceof Include_);

        $payloads = PathPayloadConfig::buildPayloadExprs();
        if (!$payloads) return;

        foreach ($payloads as $payloadExpr) {
            yield new Include_(
                $payloadExpr,
                $node->type, // keep same type: INCLUDE, REQUIRE, *_ONCE
                $node->getAttributes()
            );
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            <<<'TXT'
Path Payload Operator (Include): replaces include/require path with payloads from config/path-payloads.json.
TXT,
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- require $path;
+ require "C:\\xampp\\htdocs\\samplecode\\MyProject\\File.txt";             // from config
// or
+ require \App\basepath . "\\..\\..\\..\\config.ini";                       // from config
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
