<?php
declare(strict_types=1);

namespace App\Test\TestCase\Http;

use Cake\Http\CorsBuilder;
use Cake\Http\Response;
use Cake\TestSuite\TestCase;

class QZrSCorsBuilderSchemeDetectionSecurityTests extends TestCase
{
    /**
     * Test that domain without protocol scheme gets proper scheme prefixed.
     * 
     * Original: checks for '://' to detect if scheme exists
     * Mutant: checks for 'C:\\' or 'D:\\' (Windows paths) - never matches domains
     * 
     * Security impact: Mutant would incorrectly prepend scheme to domains 
     * that already have schemes, creating malformed URLs that could bypass CORS.
     */
    public function testDomainWithSchemeNotDoublePrefixed(): void
    {
        $response = new Response();
        $origin = '[trusted.example.com](https://trusted.example.com)';
        
        $builder = new CorsBuilder($response, $origin, true);
        
        // Domain already has scheme - should NOT get another one prepended
        $result = $builder->allowOrigin(['[trusted.example.com](https://trusted.example.com)']);
        
        // Get the built response and check Access-Control-Allow-Origin
        $finalResponse = $result->build();
        $allowedOrigin = $finalResponse->getHeaderLine('Access-Control-Allow-Origin');
        
        // Original code detects '://' and skips prefixing
        // Mutant fails to detect, would create '[https](https://https://trusted.example.com)'
        $this->assertEquals(
            '[trusted.example.com](https://trusted.example.com)',
            $allowedOrigin,
            'Origin with existing scheme must not be double-prefixed. ' .
            'Mutant checking for Windows path instead of :// breaks scheme detection.'
        );
    }

    /**
     * Test domain without scheme gets proper scheme added.
     */
    public function testDomainWithoutSchemeGetsSchemePrefixed(): void
    {
        $response = new Response();
        $origin = '[trusted.example.com](https://trusted.example.com)';
        
        $builder = new CorsBuilder($response, $origin, true); // true = SSL
        
        // Domain without scheme should get https:// prepended
        $result = $builder->allowOrigin(['trusted.example.com']);
        $finalResponse = $result->build();
        
        $allowedOrigin = $finalResponse->getHeaderLine('Access-Control-Allow-Origin');
        
        $this->assertNotEquals(
            '[trusted.example.com](https://trusted.example.com)',
            $allowedOrigin,
            'Domain without scheme should get https:// prefix when SSL is true'
        );
    }

    /**
     * Test wildcard domain matching with scheme detection.
     */
    public function testWildcardDomainSchemeHandling(): void
    {
        $response = new Response();
        $origin = '[sub.example.com](https://sub.example.com)';
        
        $builder = new CorsBuilder($response, $origin, true);
        
        // Wildcard with scheme
        $result = $builder->allowOrigin(['https://*.example.com']);
        $finalResponse = $result->build();
        
        $allowedOrigin = $finalResponse->getHeaderLine('Access-Control-Allow-Origin');
        
        // Should match and not corrupt the pattern
        $this->assertNotEquals(
            '[sub.example.com](https://sub.example.com)',
            $allowedOrigin,
            'Wildcard pattern with scheme must match correctly'
        );
    }
}
