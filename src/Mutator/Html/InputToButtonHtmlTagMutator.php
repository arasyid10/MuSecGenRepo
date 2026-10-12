<?php
declare(strict_types=1);

namespace App\Mutator\Html;

use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Scalar\Encapsed;
use PhpParser\Node\Scalar\EncapsedStringPart;

final class InputToButtonHtmlTagMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if ($node instanceof String_) return (bool) preg_match('/<\s*input\b/i', $node->value);
        if ($node instanceof Encapsed) {
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart && preg_match('/<\s*input\b/i', $p->value)) return true;
            }
        }
        return false;
    }

    public function mutate(Node $node): iterable
    {
        $open  = static fn(string $s) => preg_replace('/<\s*input(\s|\/|>)/i', '<button$1', $s);
        $close = static fn(string $s) => preg_replace('/<\s*\/\s*input\s*>/i', '</button>', $s);

        if ($node instanceof String_) {
            yield new String_($open($close($node->value)), $node->getAttributes());
            return;
        }
        if ($node instanceof Encapsed) {
            $parts = [];
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart) {
                    $parts[] = new EncapsedStringPart($open($close($p->value)), $p->getAttributes());
                } else {
                    $parts[] = $p;
                }
            }
            yield new Encapsed($parts, $node->getAttributes());
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces <input> with <button> in string/encapsed HTML.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo "<input type=\"submit\">";
+ echo "<button type=\"submit\">";
DIFF
        );
    }

    public function getName(): string { return self::class; }
}
