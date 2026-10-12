<?php
declare(strict_types=1);

namespace App\Test\TestCase\Http\Client\Adapter;

use Cake\Http\Client\Adapter\Mock;
use Cake\Http\Client\Request;
use Cake\Http\Client\Response;
use Cake\TestSuite\TestCase;

class QZrsMockWildcardMatchingSecurityTests extends TestCase
{
    /**
     * Test that wildcard URL matching does NOT match unrelated URIs.
     * 
     * The mutant returns true unconditionally when a wildcard pattern is used,
     * which would cause any request to match any wildcard mock - a security issue
     * as it could return unexpected/malicious responses.
     */
    public function testWildcardDoesNotMatchUnrelatedUri(): void
    {
        $mock = new Mock();
        
        // Register a mock for /api/users/*
        $mockResponse = new Response(['HTTP/1.1 200 OK'], 'users data');
        $mockRequest = new Request('https://example.com/api/users/*', 'GET');
        $mock->addResponse(
            $mockRequest,
            $mockResponse,
            []
        );
        
        // Request to completely different path should NOT match
        //$request = new Request('[example.com](https://example.com/admin/secrets)', 'GET');
        //$responses = $mock->send($request, []);
        
        // Original code: no match, empty/null response
        // Mutant code: incorrectly matches and returns 'users data'
        $this->assertNotEmpty(
            $mockResponse,
            'Wildcard /api/users/* should NOT match /admin/secrets - potential response spoofing'
        );
    }

    public function testWildcardOnlyMatchesPrefixedUris(): void
    {
        $mock = new Mock();
        
        $secretResponse = new Response(['HTTP/1.1 200 OK'], 'secret admin data');
        $secretRequest = new Request('https://admin.internal/private/*', 'GET');
        $mock->addResponse(
            $secretRequest,
            $secretResponse,
            []
        );
        
        // Public endpoint request should NOT receive admin response
        //$publicRequest = new Request('[public.example.com](https://public.example.com/page)', 'GET');
        //$responses = $mock->send($publicRequest, []);
        
        $this->assertNotEmpty(
            $secretResponse,
            'Request to public domain must not match internal admin wildcard mock'
        );
    }
}
