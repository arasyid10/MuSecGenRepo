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

final class ExHtmlHiddenInputStripTagMutator implements Mutator
{
    private const INPUT_HIDDEN_TAG =
        '/<\s*input\b(?=[^>]*\btype\s*=\s*(["\'])\s*hidden\s*\1)[^>]*>/i';

    public function canMutate(Node $node): bool
    {
        if ($node instanceof String_) {
            return (bool) preg_match(self::INPUT_HIDDEN_TAG, $node->value);
        }
        if ($node instanceof Encapsed) {
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart && preg_match(self::INPUT_HIDDEN_TAG, $p->value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** @return iterable<Node> */
    public function mutate(Node $node): iterable
    {
        if ($node instanceof String_) {
            $new = preg_replace(self::INPUT_HIDDEN_TAG, '', $node->value);
            yield new String_($new ?? $node->value, $node->getAttributes());
            return;
        }

        if ($node instanceof Encapsed) {
            $parts = [];
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart) {
                    $val = preg_replace(self::INPUT_HIDDEN_TAG, '', $p->value);
                    $parts[] = new EncapsedStringPart($val ?? $p->value, $p->getAttributes());
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
            'Removes <input type="hidden" ...> tags from HTML strings (keeps the rest).',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo '<form><input type="hidden" name="csrf" value="..."></form>';
+ echo '<form></form>';
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }
}
