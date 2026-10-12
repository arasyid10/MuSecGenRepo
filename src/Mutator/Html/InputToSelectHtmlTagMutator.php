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

final class InputToSelectHtmlTagMutator implements Mutator
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
        $replaceOpen  = static fn(string $s) => preg_replace('/<\s*input(\s|\/|>)/i', '<select$1', $s);
        $replaceClose = static fn(string $s) => preg_replace('/<\s*\/\s*input\s*>/i', '</select>', $s);

        if ($node instanceof String_) {
            yield new String_($replaceOpen($replaceClose($node->value)), $node->getAttributes());
            return;
        }
        if ($node instanceof Encapsed) {
            $parts = [];
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart) {
                    $parts[] = new EncapsedStringPart($replaceOpen($replaceClose($p->value)), $p->getAttributes());
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
            'Replaces <input> with <select> in string/encapsed HTML.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo "<input name=\"x\">";
+ echo "<select name=\"x\">";
DIFF
        );
    }

    public function getName(): string { return self::class; }
}
