<?php
declare(strict_types=1);

namespace App\Mutator\Html;

use App\Mutator\Support\HtmlValueConfig;
use Infection\Mutator\Definition;
use Infection\Mutator\Mutator;
use Infection\Mutator\MutatorCategory;
use PhpParser\Node;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Scalar\Encapsed;
use PhpParser\Node\Scalar\EncapsedStringPart;

/**
 * Mutates:  <tag ... value="ANY" ...>  →  <tag ... value="<PREDICTABLE_TOKEN>" ...>
 *
 * - Bekerja untuk String_ & Encapsed (heredoc/interpolasi).
 * - Case-insensitive utk "value=" dan nama tag.
 * - Hanya mengganti KEMUNCULAN PERTAMA per literal (granular).
 * - Token diambil dari config (atau default 100 token "mudah ditebak").
 */
final class HtmlValueTokenMutator implements Mutator
{
    public function canMutate(Node $node): bool
    {
        if ($node instanceof String_) {
            return $this->hasValueAttribute($node->value);
        }
        if ($node instanceof Encapsed) {
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart && $this->hasValueAttribute($p->value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @return iterable<Node>
     */
    public function mutate(Node $node): iterable
    {
        $tokens = HtmlValueConfig::getTokens(100);
        if ($node instanceof String_) {
            foreach ($tokens as $tok) {
                $mut = $this->replaceFirstValue($node->value, $tok);
                if ($mut !== $node->value) {
                    yield new String_($mut, $node->getAttributes());
                }
            }
            return;
        }

        if ($node instanceof Encapsed) {
            foreach ($tokens as $tok) {
                $changed = false;
                $done = false;
                $parts = [];
                foreach ($node->parts as $p) {
                    if ($p instanceof EncapsedStringPart && !$done) {
                        [$newVal, $did] = $this->replaceFirstValueWithFlag($p->value, $tok);
                        $changed = $changed || $did;
                        $done = $done || $did;
                        $parts[] = new EncapsedStringPart($newVal, $p->getAttributes());
                    } else {
                        $parts[] = $p;
                    }
                }
                if ($changed) {
                    yield new Encapsed($parts, $node->getAttributes());
                }
            }
        }
    }

    public static function getDefinition(): Definition
    {
        return new Definition(
            'Replaces HTML value="..." with predictable tokens (100 variants) from config or defaults, inside string/encapsed literals.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo '<input type="hidden" name="csrf" value="A1b2C3D4E5F6">';
+ echo '<input type="hidden" name="csrf" value="phpsessid">';
# atau
+ echo '<input type="hidden" name="csrf" value="token0001">';
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* ---------------- helpers ---------------- */

    private function hasValueAttribute(string $s): bool
    {
        // cari <tag ... value="..."> dengan kutip ' atau "
        return (bool) preg_match(
            '/<\s*[a-z][\w:-]*\b[^>]*\bvalue\s*=\s*(["\']).*?\1/si',
            $s
        );
    }

    private function replaceFirstValue(string $s, string $newToken): string
    {
        [$out] = $this->replaceFirstValueWithFlag($s, $newToken);
        return $out;
    }

    /** @return array{0:string,1:bool} */
    private function replaceFirstValueWithFlag(string $s, string $newToken): array
    {
        $replaced = false;
        $out = preg_replace_callback(
            // (<... value=)(quote)(current)(same quote)
            '/(<\s*[a-z][\w:-]*\b[^>]*\bvalue\s*=\s*)(["\'])(.*?)\2/si',
            static function (array $m) use (&$replaced, $newToken): string {
                if ($replaced) return $m[0];
                $replaced = true;
                // $m[1] = prefix + "value="
                // $m[2] = quote (single/double), dipertahankan
                // $m[3] = old token
                return $m[1] . $m[2] . $newToken . $m[2];
            },
            $s
        );
        return [$out ?? $s, $replaced];
    }
}
