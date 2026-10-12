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

/**
 * Jika sebuah literal (String_ / Encapsed) mengandung <input type="hidden" ...>,
 * maka seluruh literal dimutasi menjadi string kosong "".
 */
final class ExHtmlHiddenInputWipeStringMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if ($node instanceof String_) {
            return $this->hasHiddenInput($node->value);
        }
        if ($node instanceof Encapsed) {
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart && $this->hasHiddenInput($p->value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** @return iterable<Node> */
    public function mutate(Node $node): iterable
    {
        // Selalu ganti seluruh literal menjadi "" (string kosong)
        yield new String_('', $node->getAttributes());
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'If a string contains <input type="hidden" ...>, replace the whole string with "".',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo '<form><input type="hidden" name="csrf" value="..."></form>';
+ echo '';
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* ------------ helpers ------------ */

    private function hasHiddenInput(string $s): bool
    {
        // Deteksi tag <input ... type="hidden" ...> atau 'hidden' (case-insensitive)
        // Gunakan lookahead agar order atribut bebas.
        return (bool) preg_match(
            '/<\s*input\b(?=[^>]*\btype\s*=\s*(["\'])\s*hidden\s*\1)[^>]*>/i',
            $s
        );
    }
}
