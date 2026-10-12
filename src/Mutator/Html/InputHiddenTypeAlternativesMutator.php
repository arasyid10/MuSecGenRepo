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
 * Mutates: <input ... type="hidden" ...>  →  <input ... type="<ALT>" ...>
 * ALT ∈ { text, password, checkbox, radio, file, submit, reset, button, number, date, email, url }
 *
 * - Bekerja di literal string & encapsed (heredoc / "string dengan {$var}").
 * - Case-insensitive untuk "input" & "hidden".
 * - Menghindari false positive di tag lain (mencari pola <input ... type=...> saja).
 * - Mempertahankan kutip (' atau ") & spasi sekitar nilai.
 */
final class InputHiddenTypeAlternativesMutator implements Mutator
{
    /** @var string[] */
    private const TARGET_TYPES = [
        'text', 'password', 'checkbox', 'radio', 'file',
        'submit', 'reset', 'button', 'number', 'date', 'email', 'url',
    ];

    public function canMutate(Node $node): bool
    {
        if ($node instanceof String_) {
            return $this->hasInputHiddenType($node->value);
        }
        if ($node instanceof Encapsed) {
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart && $this->hasInputHiddenType($p->value)) {
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
        if ($node instanceof String_) {
            foreach (self::TARGET_TYPES as $alt) {
                $mut = $this->replaceHiddenType($node->value, $alt);
                if ($mut !== $node->value) {
                    yield new String_($mut, $node->getAttributes());
                }
            }
            return;
        }

        if ($node instanceof Encapsed) {
            foreach (self::TARGET_TYPES as $alt) {
                $changed = false;
                $parts = [];
                foreach ($node->parts as $p) {
                    if ($p instanceof EncapsedStringPart) {
                        $newVal = $this->replaceHiddenType($p->value, $alt);
                        $changed = $changed || ($newVal !== $p->value);
                        $parts[] = new EncapsedStringPart($newVal, $p->getAttributes());
                    } else {
                        $parts[] = $p; // variabel/expr dibiarkan utuh
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
            'Replaces <input type="hidden"> with alternative types (text/password/checkbox/radio/file/submit/reset/button/number/date/email/url) within string or encapsed literals.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo '<input type="hidden" name="csrf">';
+ echo '<input type="text" name="csrf">';
# atau
+ echo '<input type="password" name="csrf">';
# dst...
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* ------------ helpers ------------ */

    /** Deteksi ada <input ... type="hidden" ...> (atau 'hidden'), case-insensitive. */
    private function hasInputHiddenType(string $s): bool
    {
        return (bool) preg_match(
            '/<\s*input\b[^>]*\btype\s*=\s*(["\'])\s*hidden\s*\1/i',
            $s
        );
    }

    /**
     * Ganti 'hidden' dengan $alt di dalam atribut type milik tag <input ...>.
     * Menjaga kutip & spasi di sekitarnya agar stabil.
     */
    private function replaceHiddenType(string $s, string $alt): string
    {
        return (string) preg_replace_callback(
            '/(<\s*input\b[^>]*\btype\s*=\s*)(["\'])(\s*)hidden(\s*)(\2)/i',
            static function (array $m) use ($alt): string {
                // $m[1] = prefix "<input ... type="
                // $m[2] = kutip pembuka (' atau ")
                // $m[3] = spasi sebelum 'hidden' (opsional)
                // $m[4] = spasi sesudah 'hidden' (opsional)
                // $m[5] = kutip penutup (sama seperti $m[2])
                return $m[1] . $m[2] . $m[3] . $alt . $m[4] . $m[5];
            },
            $s
        );
    }
}
