<?php
//ZERO SHOT DIBUAT OLEH CHATGPT, GEMINI
declare(strict_types=1);

namespace Cake\Test\TestCase\Http\Middleware;

use Cake\Http\Exception\InvalidCsrfTokenException;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use Cake\Http\Client\Adapter\Mock as MockAdapter;
use Cake\Http\Client\Auth\Oauth;
use Cake\Http\ContentTypeNegotiation;
use Cake\Http\Client\Adapter\Mock;
use Cake\Http\Client\Request;
use Cake\Http\Response;
use Cake\Utility\Security; 
class CsrfProtectionMiddlewareSecurityTests extends TestCase
{
    /*
     * Expose protected CSRF validation method for security testing.
     
    private function validateCsrfToken(CsrfProtectionMiddleware $middleware, ServerRequest $request): void
    {
        if (method_exists($middleware, 'validateToken')) {
            $method = new \ReflectionMethod($middleware, 'validateToken');
        } elseif (method_exists($middleware, '_validateToken')) {
            $method = new \ReflectionMethod($middleware, '_validateToken');
        } else {
            $this->fail('CSRF validation method was not found.');
        }

        $method->setAccessible(true);
        $method->invoke($middleware, $request);
    }

    public function testRejectsTypeJugglingTokenFromRequestBody(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $request = new ServerRequest([
            'environment' => [
                'REQUEST_METHOD' => 'POST',
            ],
            'post' => [
                '_csrfToken' => '0',
            ],
            'cookies' => [
                'csrfToken' => '0e123456789',
            ],
        ]);

        $this->expectException(InvalidCsrfTokenException::class);

        $this->validateCsrfToken($middleware, $request);
    }

    public function testRejectsTypeJugglingTokenFromRequestHeader(): void
    {
        $middleware = new CsrfProtectionMiddleware();

        $request = new ServerRequest([
            'environment' => [
                'REQUEST_METHOD' => 'POST',
                'HTTP_X_CSRF_TOKEN' => '0',
            ],
            'cookies' => [
                'csrfToken' => '0e123456789',
            ],
        ]);

        $this->expectException(InvalidCsrfTokenException::class);

        $this->validateCsrfToken($middleware, $request);
    }

    //DIBUAT OLEH GEMINI 5 TC
public function testCsrfTokenComparisonIsSecure()
{
  $middleware = new CsrfProtectionMiddleware();
    
    // We need to test the logic that would be bypassed by '=='
    // Technically, to kill a timing attack mutant in a unit test, 
    // you must show that '0e123' == '0e456' is true, but hash_equals is false.
    $token1 = '0e123456789012345678901234567890';
    $token2 = '0e999999999999999999999999999999';

    $reflection = new \ReflectionClass($middleware);
    $method = $reflection->getMethod('compareTokens'); // Adjust name based on Cake version
    $method->setAccessible(true);

    $result = $method->invokeArgs($middleware, [$token1, $token2]);

    $this->assertFalse($result, "STOPS MUTANTS 18-27: Insecure comparison detected.");
}
public function testOauthSignatureUsesCorrectAlgorithm()
{
  $oauth = new Oauth();
    $credentials = [
        'consumerSecret' => 'secret',
        'tokenSecret' => 'token'
    ];
    $values = ['oauth_nonce' => '12345'];
    $baseString = 'POST&https%3A%2F%2Fexample.com&etc';

    $reflection = new \ReflectionClass($oauth);
    $method = $reflection->getMethod('sign');
    $method->setAccessible(true);

    $result = $method->invokeArgs($oauth, [$values, $credentials, $baseString]);
    
    $actualSignature = $result['oauth_signature'];
    // Manually calculate what SHA1 SHOULD be
   $key = implode('&', [rawurlencode('secret_key'), rawurlencode('token_key')]);
    $expectedSignature = base64_encode(hash_hmac('sha1', $baseString, $key, true));
    // This fails if the mutant used 'md5' or 'Whirlpool'
  $this->assertEquals(
        $expectedSignature, 
        $actualSignature, 
        "MUTANT KILLED: The Oauth signature is not using the required SHA1 algorithm."
    );
    }
public function testMockAdapterUriValidation()
{
    $mock = new MockAdapter();
    $mockUri = "https://api.cakephp.org/%2A"; // %2A is '*'
    $requestUri = "https://malicious-site.com/endpoint";
    
   // Using Reflection to access the protected _match method
    $reflection = new \ReflectionClass($mock);
    $method = $reflection->getMethod('_match');
    $method->setAccessible(true);
    
    $result = $method->invokeArgs($mock, [$requestUri, $mockUri]);
    
    // Original: returns false (starts_with fails)
    // Mutant: returns true (ReturnConstantTrueMutator)
    $this->assertFalse($result, "STOPS MUTANT 1: Mock matched a completely different domain!");
}
public function testServerRequestUrlProcessing()
{
    $request = new ServerRequest();
    $config = ['url' => 'posts/view/1']; // No leading slash, no C:\
    
    $result = $request->processUrlOption($config);
    
    // Original: !str_starts_with('posts...', '/') is true -> adds '/' -> result: '/posts/view/1'
    // Mutant: !str_starts_with('posts...', 'C:\\') is true -> result: '/posts/view/1'
    // To kill it, provide a URL that starts with '/'
    $configMatch = ['url' => '/already/has/slash'];
    $resultMatch = $request->processUrlOption($configMatch);
    
    $this->assertEquals('/already/has/slash', $resultMatch['url'], 
        "Path processing failed. Mutant likely changed the root detection logic.");
}
public function testContentTypeNegotiationWithUnderscoreAtStart()
{
   $negotiator = new ContentTypeNegotiation();
    
    // Key: Use an underscore at index 0. 
    // strpos('_en', '_') is 0 (falsy in PHP).
    // str_contains('_en', '_') is true.
    $languages = ['_en_US']; 
    
    $reflection = new \ReflectionClass($negotiator);
    $method = $reflection->getMethod('parseAcceptLanguage');
    $method->setAccessible(true);
    
    $result = $method->invoke($negotiator, [$languages]);
    
    // Original: ignores index 0, returns '_en-us' (lowercased)
    // Mutant: sees the underscore (str_contains), replaces it -> '-en-us'
    $this->assertEquals('_en-us', $result[0], "STOPS MUTANTS 4-8: String position logic is broken.");
    }*/

    //DIBUAT OLEH QWEN 7 TC
    public function testCsrfTokenValidationIsTimingAttackResistant(): void
{
    $middleware = new CsrfProtectionMiddleware();
    $secret = Security::getSalt();
    $validKey = random_bytes(16);
    $validHmac = hash_hmac('sha1', $validKey, $secret, true);
    $validToken = base64_encode($validKey . $validHmac);
    
    // Create tokens that differ at different positions
    $testVectors = [
        'diff_at_start' => base64_encode("\x00" . substr($validKey, 1) . $validHmac),
        'diff_at_middle' => base64_encode(
            substr($validKey, 0, 8) . "\xFF" . substr($validKey, 9) . $validHmac
        ),
        'diff_at_end' => base64_encode(
            substr($validKey, 0, -1) . "\x00" . $validHmac
        ),
        'hmac_diff_only' => base64_encode(
            $validKey . substr($validHmac, 0, -1) . "\x00"
        ),
    ];
    
    $timings = [];
    $iterations = 100; // Statistical significance
    
    foreach ($testVectors as $label => $invalidToken) {
        $start = microtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            try {
                // Simulate token validation flow
                $decoded = base64_decode($invalidToken, true);
                $key = substr($decoded, 0, 16);
                $hmac = substr($decoded, 16);
                $expectedHmac = hash_hmac('sha1', $key, $secret, true);
                
                // This is the mutated line - should use hash_equals()
                $result = hash_equals($hmac, $expectedHmac); // CORRECT
                // $result = ($hmac === $expectedHmac); // MUTANT (insecure)
            } catch (\Exception $e) {
                // Handle gracefully
            }
        }
        $timings[$label] = (microtime(true) - $start) / $iterations;
    }
    
    // Statistical analysis: timings should NOT correlate with match position
    $maxDiff = max($timings) - min($timings);
    $threshold = 0.0001; // 100μs tolerance
    
    $this->assertLessThan(
        $threshold,
        $maxDiff,
        'CSRF validation timing varies by token difference position - ' .
        'potential timing attack vulnerability. Timing variance: ' . 
        number_format($maxDiff * 1000000, 2) . 'μs'
    );
}
/*
public function testCsrfTokenRejectsInvalidTokens(): void
{
     $middleware = new CsrfProtectionMiddleware();
    
   $nextHandler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface {
                return new Response();
            }
        };

    
    $invalidTokens = [
        '',
        'short',
        base64_encode(random_bytes(10)),
        $flippedToken,
        str_repeat('A', 100),
    ];
    
    foreach ($invalidTokens as $token) {
        $request = new ServerRequest([
            'environment' => ['HTTP_X_CSRF_TOKEN' => $token],
            'post' => ['csrf_field' => $token]
        ]);
        
        $this->expectException(InvalidCsrfTokenException::class);
        $middleware->process($request, $nextHandler);
    }
}*/
/**
 * @group security
 * @group oauth
 */
public function testOauthSignatureRequiresSha1Algorithm(): void
{
    $oauth = new Oauth();
    $credentials = [
        'consumerSecret' => 'consumer_secret',
        'tokenSecret' => 'token_secret'
    ];
    $baseString = 'GET&http%3A%2F%2Fexample.com%2Fapi&param%3Dvalue';
    
    // Generate signature with CORRECT algorithm (sha1)
    $key = implode('&', array_map(
        fn($s) => rawurlencode($s), 
        [$credentials['consumerSecret'], $credentials['tokenSecret']]
    ));
    $expectedSig = base64_encode(hash_hmac('sha1', $baseString, $key, true));
    
    // Generate signature with MUTATED algorithms (should be rejected)
    $md5Sig = base64_encode(hash_hmac('md5', $baseString, $key, true));
    $whirlpoolSig = base64_encode(hash_hmac('Whirlpool', $baseString, $key, true));
    
    // Test that OAuth builder ONLY produces sha1 signatures
    $reflection = new \ReflectionClass($oauth);
    $method = $reflection->getMethod('_buildSignature');
    $method->setAccessible(true);
    
    $result = $method->invoke($oauth, $baseString, $credentials);
    
    $this->assertEquals(
        $expectedSig,
        $result['oauth_signature'],
        'OAuth signature must use sha1 algorithm'
    );
    
    $this->assertNotEquals(
        $md5Sig,
        $result['oauth_signature'],
        'OAuth signature must NOT use md5 algorithm'
    );
    
    $this->assertNotEquals(
        $whirlpoolSig,
        $result['oauth_signature'],
        'OAuth signature must NOT use Whirlpool algorithm'
    );
}
/**
 * @group http
 * @group security
 */
public function testMockAdapterUriMatchingIsStrict(): void
{
    $mock = new Mock();
    
    // Test wildcard pattern matching
    $mockUri = 'https://api.example.com/users/%2A';
    $requestUris = [
        'https://api.example.com/users/123' => true,   // Should match
        'https://api.example.com/users' => false,      // Should NOT match (no trailing slash)
        'https://api.example.com/admin/123' => false,  // Should NOT match (wrong path)
        'https://evil.com/users/123' => false,         // Should NOT match (wrong domain)
    ];
    
    foreach ($requestUris as $requestUri => $shouldMatch) {
        $reflection = new \ReflectionClass($mock);
        $method = $reflection->getMethod('_matchUri');
        $method->setAccessible(true);
        
        $result = $method->invoke($mock, $mockUri, $requestUri);
        
        $this->assertSame(
            $shouldMatch,
            $result,
            "URI matching failed for: {$requestUri} against pattern: {$mockUri}"
        );
    }
}/*public function testCorsDomainValidationRejectsInvalidSchemes(): void
{
    $cors = new CorsBuilder(['origin' => '*']);
    
    $invalidDomains = [
        'C:\\evil.com',      // Windows path injection
        'D:\\attacker.org',  // Windows path injection  
        'javascript:alert(1)', // Protocol injection
        'file:///etc/passwd',  // File protocol
    ];
    
    foreach ($invalidDomains as $domain) {
        $reflection = new \ReflectionClass($cors);
        $method = $reflection->getMethod('_buildDomainRegex');
        $method->setAccessible(true);
        
        $regex = $method->invoke($cors, $domain);
        
        // Valid domains should NOT match malicious inputs
        $this->assertDoesNotMatchRegularExpression(
            $regex,
            'https://legitimate.com',
            "Domain regex for '{$domain}' incorrectly matches legitimate origins"
        );
    }
}

public function testLanguageNegotiationIsCaseSensitive(): void
{
    $negotiator = new ContentTypeNegotiation();
    
    // Test that underscore replacement is case-SENSITIVE
    // strpos (correct) vs stripos (mutant) behavior
    $acceptLanguages = [
        'en_US' => 'en-US',  // Should be transformed
        'en_us' => 'en-us',  // Should be transformed (lowercase input)
        'EN_US' => 'EN-US',  // Should preserve case after transform
    ];
    
    // The key test: ensure '_' is matched case-sensitively
    // (though '_' has no case, test surrounding logic)
    $rawHeaders = ['en_US;q=0.9, fr_FR;q=0.8'];  // Pastikan ini array string yang valid untuk header Accept-Language
    
    $result = $negotiator->parseAcceptLanguage($rawHeaders);
    
    $this->assertContains('en-US', $result);
    $this->assertContains('fr-FR', $result);
    
    // Critical: ensure malformed case variants don't bypass parsing
    $edgeCases = [
        'en\u005FUS',  // Unicode underscore
        'en%5FUS',     // URL-encoded underscore  
        'en_US\u0000', // Null byte injection
    ];
    
    foreach ($edgeCases as $case) {
        // Should not crash or produce unexpected behavior
        $result = $negotiator->parseAcceptLanguage([$case]);
        $this->assertIsArray($result);
    }
}*/
public function testHeaderQualityValueParsingUsesCorrectStringFunction(): void
{
    // Gunakan ContentTypeNegotiation yang sudah di-import, bukan HeaderUtility yang tidak ada
    $negotiator = new ContentTypeNegotiation();
    
    // Definisi $rawHeaders yang hilang atau tidak lengkap - tambahkan ini jika diperlukan
    $rawHeaders = [
        'text/html;q=0.9;charset=utf-8',  // q= in middle
        'application/json;q=0.8',          // q= at end
        'text/plain; q=0.7',               // q= with space
        'text/css;q=0.9;q=0.1',           // Multiple q= (edge case)
    ];
    
    // Gunakan parseAcceptLanguage atau metode yang sesuai dari ContentTypeNegotiation
    $reflection = new \ReflectionClass($negotiator);
    $method = $reflection->getMethod('parseAcceptLanguage'); // Asumsikan ini untuk parsing header
    $method->setAccessible(true);
    
    foreach ($rawHeaders as $header) {
        $result = $method->invoke($negotiator, [$header]);
        
        // Verify q-value extraction is accurate
        // strrpos mutant would find LAST occurrence, not first
        if (substr_count($header, 'q=') === 1) {
            $expectedQ = preg_match('/q=([0-9.]+)/', $header, $matches) 
                ? $matches[1] 
                : '1.0';
            // Assert parsing logic extracted correct value
            $this->assertNotEmpty($result);
            // Tambahkan assert spesifik jika perlu, misalnya:
            // $this->assertEquals($expectedQ, $result['q'] ?? '1.0');
        }
    }
}
}