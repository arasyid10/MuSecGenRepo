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

final class InputToLabelHtmlTagMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        return $this->hasInputTag($node);
    }

    public function mutate(Node $node): iterable
    {
        yield $this->mutateTo($node, 'label');
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces <input> HTML tag with <label> within string/encapsed literals.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo "<input type=\"text\" name=\"q\">";
+ echo "<label type=\"text\" name=\"q\">";
DIFF
        );
    }

    public function getName(): string { return self::class; }

    private function hasInputTag(Node $node): bool
    {
        if ($node instanceof String_) {
            return (bool) preg_match('/<\s*input\b/i', $node->value);
        }
        if ($node instanceof Encapsed) {
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart && preg_match('/<\s*input\b/i', $p->value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private function mutateTo(Node $node, string $tag): Node
    {
        $replaceOpen  = static fn(string $s) => preg_replace('/<\s*input(\s|\/|>)/i', '<' . $tag . '$1', $s);
        $replaceClose = static fn(string $s) => preg_replace('/<\s*\/\s*input\s*>/i', '</' . $tag . '>', $s);

        if ($node instanceof String_) {
            $val = $replaceOpen($replaceClose($node->value));
            return new String_($val, $node->getAttributes());
        }

        if ($node instanceof Encapsed) {
            $parts = [];
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart) {
                    $val = $replaceOpen($replaceClose($p->value));
                    $parts[] = new EncapsedStringPart($val, $p->getAttributes());
                } else {
                    $parts[] = $p; // variabel/expr tak diubah
                }
            }
            return new Encapsed($parts, $node->getAttributes());
        }

        return $node;
    }
}
