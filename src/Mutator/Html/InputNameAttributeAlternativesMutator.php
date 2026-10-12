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
 * Mutates: <tag ... name="ANY" ...> → <tag ... name="<ALT>" ...>
 * ALT ∈ { csrf-token, token, xsrf-token, token-csrf }
 *
 * - Bekerja pada String_ dan Encapsed (heredoc / string dengan interpolasi).
 * - Case-insensitive untuk "name".
 * - Tidak menyentuh atribut lain (mis. data-name), karena pencarian menggunakan \bname\b.
 * - Hanya mengganti **kemunculan pertama** per literal untuk menjaga granularitas mutasi.
 */
final class InputNameAttributeAlternativesMutator implements Mutator
{
    /** @var string[] */
    private const ALT_NAMES = ['csrf-token', 'token', 'xsrf-token', 'token-csrf',
            'verification_code','captcha', 'captcha_token', 'recaptcha', 'recaptcha_token', 'csrf_token', 'xsrf_token',
            'token_csrf', 'csrfToken', 'xsrfToken', 'token_csrf'];
    public function canMutate(Node $node): bool
    {
        if ($node instanceof String_) {
            return $this->hasNameAttribute($node->value);
        }
        if ($node instanceof Encapsed) {
            foreach ($node->parts as $p) {
                if ($p instanceof EncapsedStringPart && $this->hasNameAttribute($p->value)) {
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
            foreach (self::ALT_NAMES as $alt) {
                $mut = $this->replaceFirstNameValue($node->value, $alt);
                if ($mut !== $node->value) {
                    yield new String_($mut, $node->getAttributes());
                }
            }
            return;
        }

        if ($node instanceof Encapsed) {
            foreach (self::ALT_NAMES as $alt) {
                $changed = false;
                $didReplaceOnce = false;
                $parts = [];
                foreach ($node->parts as $p) {
                    if ($p instanceof EncapsedStringPart && !$didReplaceOnce) {
                        [$newVal, $did] = $this->replaceFirstNameValueWithFlag($p->value, $alt);
                        $changed = $changed || $did;
                        $didReplaceOnce = $didReplaceOnce || $did;
                        $parts[] = new EncapsedStringPart($newVal, $p->getAttributes());
                    } else {
                        $parts[] = $p; // variabel/expr dibiarkan
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
            'Replaces HTML attribute name="..." with one of {csrf-token, token, xsrf-token, token-csrf} inside string/encapsed literals.',
            MutatorCategory::SEMANTIC_REDUCTION,
            null,
            <<<'DIFF'
- echo '<input type="hidden" name="auth_token">';
+ echo '<input type="hidden" name="csrf-token">';
# atau
+ echo '<input type="hidden" name="token">';
# atau
+ echo '<input type="hidden" name="xsrf-token">';
# atau
+ echo '<input type="hidden" name="token-csrf">';
DIFF
        );
    }

    public function getName(): string
    {
        return self::class;
    }

    /* =================== helpers =================== */

    /**
     * Deteksi ada atribut name="...".
     * Hanya di dalam tag HTML: <... name="...">, case-insensitive.
     */
    private function hasNameAttribute(string $s): bool
    {
        return (bool) preg_match(
            '/<\s*[a-z][\w:-]*\b[^>]*\bname\s*=\s*(["\']).*?\1/i',
            $s
        );
    }

    /**
     * Ganti **kemunculan pertama** nilai name="..." menjadi $alt (menjaga kutip).
     * @return string
     */
    private function replaceFirstNameValue(string $s, string $alt): string
    {
        [$res] = $this->replaceFirstNameValueWithFlag($s, $alt);
        return $res;
    }

    /**
     * Versi yang mengembalikan [hasil, apakah_terjadi_penggantian]
     * @return array{0:string,1:bool}
     */
    private function replaceFirstNameValueWithFlag(string $s, string $alt): array
    {
        $replaced = false;

        $out = preg_replace_callback(
            // (<tag ... name=)(quote)(value)(same quote)
            '/(<\s*[a-z][\w:-]*\b[^>]*\bname\s*=\s*)(["\'])(.*?)\2/iu',
            static function (array $m) use (&$replaced, $alt): string {
                if ($replaced) {
                    return $m[0]; // hanya ganti yang pertama
                }
                $replaced = true;
                // $m[1] = prefix "<... name="
                // $m[2] = kutip (single/double)
                // $m[3] = nilai lama
                return $m[1] . $m[2] . $alt . $m[2];
            },
            $s
        );

        return [$out ?? $s, $replaced];
    }
}
