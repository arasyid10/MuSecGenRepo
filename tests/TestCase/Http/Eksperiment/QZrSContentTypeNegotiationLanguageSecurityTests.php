<?php
declare(strict_types=1);

namespace App\Test\TestCase\Http;

use Cake\Http\ContentTypeNegotiation;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;

class ContentTypeNegotiationLanguageSecurityTests extends TestCase
{
    /**
     * Test language tag starting with underscore is handled correctly.
     * 
     * strpos('_en', '_') returns 0 (falsy in original code - no replacement)
     * str_contains('_en', '_') returns true (replacement happens)
     * stripos('_en', '_') returns 0 (same as strpos)
     * strrpos('_en', '_') returns 0 (same behavior for single occurrence)
     * strstr('_en', '_') returns '_en' (truthy - replacement happens)
     * strpbrk('_en', '_') returns '_en' (truthy - replacement happens)
     * 
     * This tests the edge case where underscore is at position 0.
     */
    public function testLanguageStartingWithUnderscoreNotTransformed(): void
    {
        $negotiation = new ContentTypeNegotiation();
        
        // Create request with malformed language tag starting with underscore
        $request = new ServerRequest([
            'environment' => [
                'HTTP_ACCEPT_LANGUAGE' => '_malicious_tag',
            ],
        ]);
        
        $languages = $negotiation->acceptLanguage($request, '');
        
        // Original behavior: strpos returns 0 (falsy), no str_replace happens
        // Mutant behavior: may return truthy, causing incorrect transformation
        // The language should remain as '_malicious_tag' (lowercased), NOT '-malicious-tag'
        $this->assertContains(
            '_malicious_tag',
            (array) $languages,
            'Language starting with underscore should NOT be transformed - strpos returns 0 (falsy)'
        );
        $this->assertNotContains(
            '-malicious-tag',
           (array) $languages,
            'Underscore at position 0 should not trigger replacement'
        );
    }

    /**
     * Test that standard locale format with underscore in middle is normalized.
     */
    public function testStandardLocaleUnderscoreReplacedWithHyphen(): void
    {
        $negotiation = new ContentTypeNegotiation();
        
        $request = new ServerRequest([
            'environment' => [
                'HTTP_ACCEPT_LANGUAGE' => 'en_US, fr_CA;q=0.8',
            ],
        ]);
        
        $languages = $negotiation->acceptLanguage($request, '') ?: [];
        
        // Both original and mutants should handle this - underscore not at position 0
        $this->assertIsArray($languages);
        $this->assertIsArray($languages, 'Expected $languages to be an array.');
        $this->assertContains('en-us', (array) $languages);
        $this->assertContains('fr-ca', (array) $languages);
    }

    /**
     * Test empty language and underscore-only cases.
     */
    public function testEdgeCaseLanguageTags(): void
    {
        $negotiation = new ContentTypeNegotiation();
        
        // Language that is just an underscore
        $request = new ServerRequest([
            'environment' => [
                'HTTP_ACCEPT_LANGUAGE' => '_',
            ],
        ]);
        
        $languages = $negotiation->acceptLanguage($request, '_');
        
        // strpos('_', '_') = 0 (falsy), should not replace
        // str_contains/strstr/strpbrk would return truthy, incorrectly replacing
        $this->assertIsArray($languages);
        if (is_array($languages)) {
            $this->assertContains('_', (array) $languages);
            $this->assertNotContains('-', (array) $languages);
        }
    }
}
