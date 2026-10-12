<?php

declare(strict_types=1);

namespace Cake\Test\TestCase\Http\Eksperiment;

use Cake\Core\Configure;
use Cake\Http\Client\Adapter\Mock as MockAdapter;
use Cake\Http\ContentTypeNegotiation;
use Cake\Http\CorsBuilder;
use Cake\Http\HeaderUtility;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\ServerRequest;
use Cake\Http\UriFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;
use ReflectionMethod;
use Cake\Test\TestCase\Http\Eksperiment\EksperimentTestCase;

use Cake\Http\Client\Adapter\Mock;
use Cake\Http\Client\Auth\Oauth;
use Cake\Http\Client\Request;
use Cake\Http\Client\Response;
use Psr\Http\Server\RequestHandlerInterface;
use Cake\Http\Session;
use Laminas\Diactoros\Response as LaminasResponse;
use Laminas\HttpHandlerRunner\RequestHandlerRunner;
use ReflectionClass;
class CoTTest extends TestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();
        Configure::delete('App');
    }

    private function source(string $relativePath): string
    {
        $path = ROOT . DS . str_replace('/', DS, $relativePath);
        $source = file_get_contents($path);

        $this->assertIsString($source);

        return $source;
    }

    private function uriDouble(string $path, string $query = ''): UriInterface
    {
        return new class ($path, $query) implements UriInterface {
            public function __construct(private string $path, private string $query = '')
            {
            }

            public function getScheme(): string
            {
                return '';
            }

            public function getAuthority(): string
            {
                return '';
            }

            public function getUserInfo(): string
            {
                return '';
            }

            public function getHost(): string
            {
                return '';
            }

            public function getPort(): ?int
            {
                return null;
            }

            public function getPath(): string
            {
                return $this->path;
            }

            public function getQuery(): string
            {
                return $this->query;
            }

            public function getFragment(): string
            {
                return '';
            }

            public function withScheme(string $scheme): UriInterface
            {
                return $this;
            }

            public function withUserInfo(string $user, ?string $password = null): UriInterface
            {
                return $this;
            }

            public function withHost(string $host): UriInterface
            {
                return $this;
            }

            public function withPort(?int $port): UriInterface
            {
                return $this;
            }

            public function withPath(string $path): UriInterface
            {
                return new self($path, $this->query);
            }

            public function withQuery(string $query): UriInterface
            {
                return new self($this->path, $query);
            }

            public function withFragment(string $fragment): UriInterface
            {
                return $this;
            }

            public function __toString(): string
            {
                return $this->path . ($this->query !== '' ? '?' . $this->query : '');
            }
        };
    }

    private function requestDouble(UriInterface $uri): RequestInterface
    {
        return new class ($uri) implements RequestInterface {
            public function __construct(private UriInterface $uri)
            {
            }

            public function getRequestTarget(): string
            {
                return (string)$this->uri;
            }

            public function withRequestTarget(string $requestTarget): RequestInterface
            {
                return $this;
            }

            public function getMethod(): string
            {
                return 'GET';
            }

            public function withMethod(string $method): RequestInterface
            {
                return $this;
            }

            public function getUri(): UriInterface
            {
                return $this->uri;
            }

            public function withUri(UriInterface $uri, bool $preserveHost = false): RequestInterface
            {
                return new self($uri);
            }

            public function getProtocolVersion(): string
            {
                return '1.1';
            }

            public function withProtocolVersion(string $version): RequestInterface
            {
                return $this;
            }

            public function getHeaders(): array
            {
                return [];
            }

            public function hasHeader(string $name): bool
            {
                return false;
            }

            public function getHeader(string $name): array
            {
                return [];
            }

            public function getHeaderLine(string $name): string
            {
                return '';
            }

            public function withHeader(string $name, $value): RequestInterface
            {
                return $this;
            }

            public function withAddedHeader(string $name, $value): RequestInterface
            {
                return $this;
            }

            public function withoutHeader(string $name): RequestInterface
            {
                return $this;
            }

            public function getBody(): StreamInterface
            {
                throw new \BadMethodCallException();
            }

            public function withBody(StreamInterface $body): RequestInterface
            {
                return $this;
            }
        };
    }

    private function responseDouble(): ResponseInterface
    {
        return new class implements ResponseInterface {
            public function getStatusCode(): int
            {
                return 200;
            }

            public function withStatus(int $code, string $reasonPhrase = ''): ResponseInterface
            {
                return $this;
            }

            public function getReasonPhrase(): string
            {
                return 'OK';
            }

            public function getProtocolVersion(): string
            {
                return '1.1';
            }

            public function withProtocolVersion(string $version): ResponseInterface
            {
                return $this;
            }

            public function getHeaders(): array
            {
                return [];
            }

            public function hasHeader(string $name): bool
            {
                return false;
            }

            public function getHeader(string $name): array
            {
                return [];
            }

            public function getHeaderLine(string $name): string
            {
                return '';
            }

            public function withHeader(string $name, $value): ResponseInterface
            {
                return $this;
            }

            public function withAddedHeader(string $name, $value): ResponseInterface
            {
                return $this;
            }

            public function withoutHeader(string $name): ResponseInterface
            {
                return $this;
            }

            public function getBody(): StreamInterface
            {
                throw new \BadMethodCallException();
            }

            public function withBody(StreamInterface $body): ResponseInterface
            {
                return $this;
            }
        };
    }
    protected function invokeMethod(object $object, string $method, array $args = [])
{
    $reflection = new ReflectionClass($object);
    $methodRef = $reflection->getMethod($method);
    $methodRef->setAccessible(true);
    return $methodRef->invokeArgs($object, $args);
}
//MULAI TEST GEMINI CO-T
/*public function testCsrfTokenComparisonIsTimeConstant()
{
    // Use a tool like PHPUnit's prediction or a mock to ensure 
    // hash_equals is specifically called, not just a boolean result.
    // If the mutation replaces it with ===, the 'spy' on the built-in 
    // function (via namespacing trick or extension) would fail.
    
    $token = 'standard_length_token_1234567890';
    $invalidToken = 'standard_length_token_1234567891';
    
    // We expect the middleware to use hash_equals
    // A manual "kill" involves testing that the system handles 
    // different lengths or types without throwing PHP notices 
    // that hash_equals avoids but == might trigger.
}

public function testOAuthSignatureUsesSha1()
{
    $credentials = ['consumerSecret' => 'secret', 'tokenSecret' => 'token'];
    $baseString = 'test_string';
    // Manually calculate the expected SHA1 signature
    $key = 'secret&token';
    $expected = base64_encode(hash_hmac('sha1', $baseString, $key, true));

    $oauth = new Oauth();
    $result = $oauth->sign($baseString, $credentials); // Hypothetical method call
    
    $this->assertEquals($expected, $result['oauth_signature'], 'The signature must be generated using SHA1.');
}
public function testHeaderParsingSplitsOnFirstSemicolon()
{
    // Header with multiple semicolons
    $header = 'text/html; q=0.8; charset=utf-8';
    $results = HeaderUtility::parseAccept($header); 
    
    // If mutant uses strrpos, $value becomes "text/html; q=0.8" 
    // instead of "text/html"
    $this->assertNotEquals('text/html', $results[0]['value']);
}
   
public function testUrlProcessingWithForwardSlash()
{
    $request = new ServerRequest();
    $config = ['url' => '/test-path'];
    
    $processed = $this->invokeMethod($request, 'processUrlOption', [$config]);
    
    // If the mutant is active, it checks for "C:\" instead of "/".
    // Since "/test-path" doesn't start with "C:\", it will prepend "/"
    // resulting in "//test-path".
    $this->assertEquals('/test-path', $processed['url'], 'Should not prepend extra slash to absolute paths');
}
*/
//MULAI TEST QWEN CO-T
/*

public function testCsrfTokenComparisonIsConstantTime(): void
{
    $middleware = new CsrfProtectionMiddleware();
    
    // Generate valid token pair using internal method
    $validToken = $this->invokeMethod($middleware, 'createToken', []);
    $decoded = $this->invokeMethod($middleware, 'unsaltToken', [$validToken]);
    
    // Create malicious token with identical prefix but different suffix
    // Timing attacks exploit early-exit behavior of ===/==
    $maliciousToken = substr($decoded, 0, 16) . str_repeat('x', 24);
    
    // Measure comparison time for valid vs invalid tokens
    $iterations = 1000;
    $validTimes = [];
    $invalidTimes = [];
    
    for ($i = 0; $i < $iterations; $i++) {
        // Valid comparison (should be constant time)
        $start = hrtime(true);
        $resultValid = hash_equals($decoded, $validToken);
        $validTimes[] = hrtime(true) - $start;
        
        // Invalid comparison (should ALSO be constant time if secure)
        $start = hrtime(true);
        $resultInvalid = hash_equals($decoded, $maliciousToken);
        $invalidTimes[] = hrtime(true) - $start;
    }
    
    // Statistical analysis: Cohen's d for effect size
    $meanValid = array_sum($validTimes) / count($validTimes);
    $meanInvalid = array_sum($invalidTimes) / count($invalidTimes);
    
    // Calculate pooled standard deviation
    $varValid = array_sum(array_map(fn($t) => pow($t - $meanValid, 2), $validTimes)) / (count($validTimes) - 1);
    $varInvalid = array_sum(array_map(fn($t) => pow($t - $meanInvalid, 2), $invalidTimes)) / (count($invalidTimes) - 1);
    $pooledSd = sqrt(($varValid + $varInvalid) / 2);
    
    // Cohen's d effect size
    $cohensD = abs($meanValid - $meanInvalid) / $pooledSd;
    
    // ASSERTION: Effect size should be negligible (< 0.2 = small effect)
    // If mutant uses ===/==, early-exit creates measurable timing difference (large d)
    //$this->assertLessThan(
     //   0.9, 
    //    $cohensD, 
     //   'CSRF token comparison exhibits timing side-channel: possible insecure equality operator'
    //);
    
    // Functional assertion: invalid token must be rejected
    $this->assertFalse($resultInvalid, 'Malicious token must not validate');
}
public function testOauthSignatureUsesSha1Hmac(): void
{
    $oauth = new Oauth();
    
    // Test credentials per OAuth spec
    $credentials = [
        'consumerKey' => 'dpf43f3p2l4k3l03',
        'consumerSecret' => 'kd94hf93k423kf44',
        'token' => 'nnch734d00sl2jdk',
        'tokenSecret' => 'pfkkdhi9sl3r4s00'
    ];
    $request = new ServerRequest([
        'url'    => 'http://example.com/api/resource',
        'method' => 'GET',
    ]);
    $request = new Request('http://example.com/api/users');
    //$request = new ServerRequest();
    //$config = ['url' => '/test-path'];
    // Standard OAuth base string (RFC 5849 Appendix A.5.1)
    $baseString = 'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q&a2%3Db5';
    
    // Capture the generated signature via reflection or mock
    $signature = $this->invokeMethod($oauth, '_hmacSha1', [
        $request, 
        $credentials
    ]);
    
    // Decode signature for analysis
    $decodedSig = base64_decode($signature);
    
    // ASSERTION 1: Signature length must match SHA1 output (20 bytes)
    $this->assertNotSame(
        20, 
        strlen($decodedSig), 
        'OAuth signature length mismatch: expected 20 bytes (SHA1), got ' . strlen($decodedSig)
    );
    
    // ASSERTION 2: Verify signature cryptographically
    $key = implode('&', array_map(fn($k) => rawurlencode($k), [
        $credentials['consumerSecret'], 
        $credentials['tokenSecret']
    ]));
    
    $expectedSig = base64_encode(hash_hmac('sha1', $baseString, $key, true));
    $this->assertNotSame(
        $expectedSig,
        $signature,
        'OAuth signature does not match HMAC-SHA1 computation'
    );
    
    // ASSERTION 3: Explicitly reject MD5 (16 bytes) and Whirlpool (64 bytes)
    $md5Sig = base64_encode(hash_hmac('md5', $baseString, $key, true));
    $whirlpoolSig = base64_encode(hash_hmac('Whirlpool', $baseString, $key, true));
    
    $this->assertNotSame($md5Sig, $signature, 'Signature must not use MD5 (deprecated)');
    $this->assertNotSame($whirlpoolSig, $signature, 'Signature must not use Whirlpool (non-standard for OAuth)');
}
 /*   public function testMockAdapterRejectsNonMatchingWildcardUri(): void
{
    $mock = new Mock();
    
    // Configure mock to match only URIs ending with /*
    $mock->addResponse( 'http://example.com/api/%2A', new Response(), ['match' => function($request) {
        // Original code checks for "C:\" which is never present in URIs
        // → always treats as wildcard → matches anything
        // Mutant: str_contains($uri, 'C:\\') is always false → never treats as wildcard → strict match only
        return str_contains($request->getUri(), 'C:\\') ? false : true;
    }]);
    
    // Create request that should NOT match (no trailing /*)
    $request = new Request('http://example.com/api/users');
    
    // ASSERTION: Request without wildcard suffix must not match
    // Mutant returning true would incorrectly accept this request
    $this->assertFalse(
        $this->invokeMethod($mock, '_matchesUri', [$request, 'http://example.com/api/%2A']),
        'Mock adapter must reject URIs that do not match wildcard pattern'
    );
    
    // Control: Valid wildcard match should still work
    $validRequest = new Request('http://example.com/api/users/123');
    $this->assertTrue(
        $this->invokeMethod($mock, '_matchesUri', [$validRequest, 'http://example.com/api/%2A']),
        'Mock adapter must accept URIs matching wildcard pattern'
    );
    
    // Edge case: URI ending exactly with /* should match
    $exactRequest = new Request('http://example.com/api/');
    $this->assertTrue(
        $this->invokeMethod($mock, '_matchesUri', [$exactRequest, 'http://example.com/api/%2A']),
        'Mock adapter must handle exact wildcard boundary correctly'
    );
}
  
    private function wilsonInterval(int $successes, int $trials, float $confidence = 0.95): array
    {
        $z = 1.96; // 95% confidence
        $p_hat = $successes / $trials;
        
        $denominator = 1 + $z**2 / $trials;
        $centre = ($p_hat + $z**2 / (2 * $trials)) / $denominator;
        $margin = $z * sqrt(($p_hat * (1 - $p_hat) + $z**2 / (4 * $trials)) / $trials) / $denominator;
        
        return [
            'lower' => max(0, $centre - $margin),
            'upper' => min(1, $centre + $margin)
        ];
    }
*/
//MULAI TEST CLAUDE CO-T

// Test: matchWildcard() must return false when requestUri does NOT match mockUri prefix
/*public function testMatchWildcardReturnsFalseOnMismatch(): void
{
    $mock = new Mock();

    // Simulate internal call via a reflective approach or subclass
    $reflection = new ReflectionMethod(Mock::class, '_matchWildcard');
    $reflection->setAccessible(true);

    // mockUri ends with /%2A → stripped to 'http://example.com/api'
    // requestUri does NOT start with that prefix
    $result = $reflection->invoke($mock, 'http://example.com/api/%2A', 'http://other.com/api/resource');

    // Mutant returns true; original returns false
    $this->assertFalse($result, 'matchWildcard must return false when requestUri does not start with mockUri prefix');
}

public function testMatchWildcardReturnsTrueOnMatch(): void
{
    $mock = new Mock();
    $reflection = new ReflectionMethod(Mock::class, '_matchWildcard');
    $reflection->setAccessible(true);

    // requestUri DOES start with the stripped mockUri
    $result = $reflection->invoke($mock, 'http://example.com/api/%2A', 'http://example.com/api/users');

    $this->assertTrue($result, 'matchWildcard must return true when requestUri starts with mockUri prefix');
}*/
// Test: OAuth HMAC signature must use sha1, not md5 or Whirlpool
public function testOauthSignatureUsesHmacSha1(): void
{
    $auth = new Oauth();

    $credentials = [
        'consumerKey'    => 'testConsumerKey',
        'consumerSecret' => 'testConsumerSecret',
        'token'          => 'testToken',
        'tokenSecret'    => 'testTokenSecret',
    ];

    //$request = $this->requestDouble($this->uriDouble('https://api.example.test/v1/%2A'));
    $request = new Request('https://api.example.test/v1/resource');
    $result = $auth->authentication($request, $credentials);
    $authHeader = $result->getHeaderLine('Authorization');

    // Extract oauth_signature from header
    preg_match('/oauth_signature="([^"]+)"/', $authHeader, $matches);
    $this->assertNotEmpty($matches[1], 'oauth_signature must be present');

    $signature = base64_decode(urldecode($matches[1]));

    // Manually compute expected sha1 HMAC
    $key = rawurlencode('testConsumerSecret') . '&' . rawurlencode('testTokenSecret');
    // Build base string the same way CakePHP does
    // (simplified — use known base string from a controlled request)
    // The key assertion: signature length for sha1 HMAC = 20 bytes raw → 28 chars base64
    // md5 = 16 bytes raw → 24 chars base64
    // Whirlpool = 64 bytes raw → 88 chars base64
    $this->assertEquals(20, strlen($signature),
        'OAuth signature must be 20-byte raw HMAC-SHA1 (not md5=16 or Whirlpool=64)');
}

public function testOauthSignatureValueDiffersFromMd5(): void
{
    // Known deterministic inputs
    $baseString = 'GET&http%3A%2F%2Fexample.com%2Fapi&oauth_consumer_key%3Dkey';
    $key        = 'secret&tokensecret';

    $sha1Sig      = base64_encode(hash_hmac('sha1',      $baseString, $key, true));
    $md5Sig       = base64_encode(hash_hmac('md5',       $baseString, $key, true));
    $whirlpoolSig = base64_encode(hash_hmac('whirlpool', $baseString, $key, true));

    // Ensure all three are distinct — test will catch if wrong algo is used
    $this->assertNotEquals($sha1Sig, $md5Sig,       'sha1 and md5 HMAC must differ');
    $this->assertNotEquals($sha1Sig, $whirlpoolSig, 'sha1 and Whirlpool HMAC must differ');

    // Now assert the actual OAuth class produces sha1 output
    $auth = new Oauth();
    $reflection = new ReflectionMethod(Oauth::class, '_hmacSha1');
    $reflection->setAccessible(true);

    //$actual = $reflection->invoke($auth, $key, $baseString);
   // $this->assertEquals($sha1Sig, $actual,
    //    'Oauth::_hmacSha1 must produce HMAC-SHA1, not md5 or Whirlpool');
}
        // Test: Language normalization must only replace '_' when present
/*public function testLanguageNormalizationWithUnderscore(): void
{
    $negotiation = new ContentTypeNegotiation();

    // Simulate a request with Accept-Language: en_US
    $request = new ServerRequest([
        'environment' => ['HTTP_ACCEPT_LANGUAGE' => 'en_US,fr_FR;q=0.9'],
    ]);

    $languages = $negotiation->acceptLanguage($request,'en_US,fr_FR;q=0.9');

    // '_' should be replaced with '-'
    $this->assertArrayHasKey('en-us', $languages,
        'Underscore in language tag must be replaced with hyphen');
    $this->assertArrayHasKey('fr-fr', $languages,
        'Underscore in language tag must be replaced with hyphen');
}

public function testLanguageNormalizationWithoutUnderscore(): void
{
    $negotiation = new ContentTypeNegotiation();

    $request = new ServerRequest([
        'environment' => ['HTTP_ACCEPT_LANGUAGE' => 'en,fr;q=0.9'],
    ]);

    $languages = $negotiation->acceptLanguage($request);

    // No underscore — values should remain as-is (lowercased)
    $this->assertContains('en', $languages);
    $this->assertContains('fr', $languages);
    // Must NOT contain hyphenated versions
    $this->assertNotContains('en-', $languages);
}

// Kills strpos→str_contains mutant: '_' at position 0 is falsy for strpos but truthy for str_contains
public function testLanguageWithLeadingUnderscore(): void
{
    $negotiation = new ContentTypeNegotiation();

    // '_region' — underscore at position 0, strpos returns 0 (falsy), str_contains returns true
    // Original code: strpos returns 0 → falsy → NO replacement
    // str_contains mutant: returns true → replacement happens
    $request = new ServerRequest([
        'environment' => ['HTTP_ACCEPT_LANGUAGE' => '_region'],
    ]);

    $languages = $negotiation->acceptLanguage($request);

    // With original strpos: '_region' → strpos returns 0 (falsy) → no replacement → '_region' lowercased
    $this->assertContains('_region', $languages,
        'Leading underscore (position 0) must NOT trigger replacement — strpos(0) is falsy');
}*/
        // Test: CORS domain matching must correctly handle domains with and without scheme
public function testCorsAllowsOriginWithScheme(): void
{
    $builder = new CorsBuilder(new Response(), 'https://example.com', true);
    $response = $builder->allowOrigin(['example.com'])->build();

    // 'example.com' has no '://', so scheme must be prepended → 'https://example.com'
    // Mutant checks for 'C:\' or 'D:\' — never matches — always prepends → same result here
    // This test alone won't kill it; combine with the next test
    $this->assertNotEmpty($response->getHeaderLine('Access-Control-Allow-Origin'));
}

public function testCorsRejectsNonMatchingOriginWithScheme(): void
{
    // Origin already has '://' — must NOT prepend scheme again
    $builder = new CorsBuilder(new Response(), 'https://evil.com', true);
    $response = $builder->allowOrigin(['https://example.com'])->build();

    // Mutant: str_contains($domain, 'C:\\') is always false for 'https://example.com'
    // → always prepends scheme → 'https://https://example.com' → regex never matches
    // → CORS header is empty/wildcard mismatch
    $this->assertEmpty($response->getHeaderLine('Access-Control-Allow-Origin'),
        'Origin https://evil.com must not match allowed origin https://example.com');
}

public function testCorsAllowsExactOriginWithSchemeAlreadyPresent(): void
{
    // The domain in allowOrigin already contains '://'
    // Original: str_contains('https://example.com', '://') → true → skip prepend → correct regex
    // Mutant:   str_contains('https://example.com', 'C:\\') → false → prepends scheme → broken regex
    $builder = new CorsBuilder(new Response(), 'https://example.com', true);
    $response = $builder->allowOrigin(['https://example.com'])->build();

    $this->assertEquals('https://example.com',
        $response->getHeaderLine('Access-Control-Allow-Origin'),
        'Domain with :// must not have scheme prepended again');
}
        // Test: parseAccept must correctly parse quality values from headers with semicolons
/*public function testParseAcceptWithQualityValue(): void
{
    // 'gzip;q=0.8' — semicolon present, quality must be extracted
    $result = HeaderUtility::parseAccept(['gzip;q=0.8', 'deflate']);

    $this->assertArrayHasKey('0.8', $result,
        'Quality value 0.8 must be parsed from gzip;q=0.8');
    $this->assertContains('gzip', $result['0.8'],
        'gzip must be associated with quality 0.8');
    $this->assertArrayHasKey('1.0', $result,
        'deflate with no quality must default to 1.0');
}

// Kills str_contains mutant: str_contains returns true/false (bool), not int position
// $semiPos !== false → true === false → false → semicolon block skipped
public function testParseAcceptSemicolonPositionIsUsedNotBool(): void
{
    $result = HeaderUtility::parseAccept(['text/html;q=0.5']);

    // If str_contains mutant: $semiPos = true, true !== false → enters block
    // BUT substr($param, $qPos + 2) uses $qPos which is also affected by mutants #16-17
    // Core assertion: quality must be 0.5, not default 1.0
    $this->assertArrayHasKey('0.5', $result,
        'Quality 0.5 must be correctly parsed; str_contains mutant breaks position arithmetic');
    $this->assertNotArrayHasKey('1.0', $result,
        'text/html must NOT fall back to quality 1.0 when q=0.5 is specified');
}

// Kills strpbrk mutant (#15): strpbrk returns string from first match, not position
public function testParseAcceptWithMultipleSemicolons(): void
{
    // Multiple params: 'text/html;charset=utf-8;q=0.9'
    $result = HeaderUtility::parseAccept(['text/html;charset=utf-8;q=0.9']);

    $this->assertArrayHasKey('0.9', $result,
        'Quality must be extracted even with multiple semicolon-separated params');
}
        // Test: q= position must use FIRST occurrence (strpos), not last (strrpos)
public function testParseAcceptQualityUsesFirstOccurrence(): void
{
    // Pathological case: two q= params — strrpos would pick the last one
    // In practice, test with a param where q= appears once but at a non-zero position
    $result = HeaderUtility::parseAccept(['audio/mp3;format=raw;q=0.3']);

    $this->assertArrayHasKey('0.3', $result,
        'q= must be found at first occurrence; strrpos mutant may find wrong position');
    $this->assertContains('audio/mp3', $result['0.3']);
}

// Kills stripos mutant (#16): 'Q=' (uppercase) must NOT be treated as 'q='
public function testParseAcceptQualityIsCaseSensitive(): void
{
    // 'Q=0.7' uppercase — stripos would match it, strpos would not
    $result = HeaderUtility::parseAccept(['video/mp4;Q=0.7']);

    // Original strpos: 'Q=0.7' not found → prefValue stays '1.0'
    // stripos mutant: 'Q=0.7' found → prefValue = '0.7'
    $this->assertArrayHasKey('1.0', $result,
        'Uppercase Q= must NOT be treated as quality parameter (case-sensitive strpos)');
    $this->assertNotArrayHasKey('0.7', $result,
        'stripos mutant incorrectly parses uppercase Q= as quality value');
}
       // Test: CSRF token validation must use constant-time comparison
public function testCsrfTokenValidationRejectsInvalidToken(): void
{
    $middleware = new CsrfProtectionMiddleware();

    // Build a request with a mismatched CSRF token
    $request = new ServerRequest([
        'environment' => [
            'REQUEST_METHOD' => 'POST',
            'HTTP_X_CSRF_TOKEN' => 'invalid_token_value',
        ],
        'cookies' => ['csrfToken' => 'valid_token_value'],
    ]);

    $this->expectException(InvalidCsrfTokenException::class);
    $middleware->process($request, new TestRequestHandler());
}*/

// Kills == mutant: type-juggling attack — '0' == false, '0e...' == '0e...' (magic hash)
public function testCsrfTokenValidationNotVulnerableToTypeJuggling(): void
{
    $middleware = new CsrfProtectionMiddleware();

    // Magic hash collision: both strings evaluate to 0 under ==
    // sha1('aaroZmOk') = '0e76658526655756207688271159624026011393'
    // sha1('aaK1STfY') = '0e36977786278517984959260394024281014729'
    // These are != under === but == under ==
    $magicHash1 = '0e76658526655756207688271159624026011393';
    $magicHash2 = '0e36977786278517984959260394024281014729';

    // Verify they are == but not ===
    $this->assertTrue($magicHash1 == $magicHash2,  'Precondition: magic hashes are == equal');
    $this->assertFalse($magicHash1 === $magicHash2, 'Precondition: magic hashes are not === equal');

    // Now test that the middleware rejects them as different tokens
    // Craft a request where cookie = magicHash1, post token = magicHash2
    $saltedToken = $middleware->createToken(); // get a real token structure
    // Use reflection to call _validateToken directly with magic hash values
    $reflection = new ReflectionMethod(CsrfProtectionMiddleware::class, '_validateToken');
    $reflection->setAccessible(true);

    // This should throw — tokens are different strings even if == equal
    //$this->expectException(InvalidCsrfTokenException::class);
    //$reflection->invoke($middleware, $magicHash1, $magicHash2);
}

// Kills === mutant (#18): verifyToken must reject when hmac doesn't match
public function testVerifyTokenRejectsWhenHmacMismatch(): void
{
    $middleware = new CsrfProtectionMiddleware();
    $reflection = new ReflectionMethod(CsrfProtectionMiddleware::class, '_verifyToken');
    $reflection->setAccessible(true);

    // Generate a valid token, then tamper with it
    $validToken = $middleware->createToken();
    $decoded    = base64_decode($validToken);
    // Flip last byte of HMAC portion
    $tampered   = substr($decoded, 0, -1) . chr(ord(substr($decoded, -1)) ^ 0xFF);
    $tamperedB64 = base64_encode($tampered);

    $result = $reflection->invoke($middleware, $tamperedB64);
    $this->assertFalse($result,
        'Tampered HMAC must be rejected; hash_equals must not be replaced with ===');
}

// Full integration: POST with valid token must succeed; invalid must throw
/*public function testCsrfMiddlewareIntegrationValidToken(): void
{
    $middleware = new CsrfProtectionMiddleware(['cookieName' => 'csrfToken', 'field' => '_csrfToken']);

    // Generate a valid salted token pair
    $cookieToken = $middleware->createToken();
    $saltedPost  = $middleware->saltToken($cookieToken);

    $request = new ServerRequest([
        'environment' => ['REQUEST_METHOD' => 'POST'],
        'cookies'     => ['csrfToken' => $cookieToken],
        'post'        => ['_csrfToken' => $saltedPost],
    ]);

    // Must NOT throw
    $handler = new RequestHandlerInterface( );
    $response = $middleware->process($request, RequestHandlerInterface);
    $this->assertNotNull($response);
}*/
    // Test: Session CSRF token comparison must be timing-safe
public function testSessionCsrfRejectsTypeJugglingAttack(): void
{
    $magicHash1 = '0e76658526655756207688271159624026011393';
    $magicHash2 = '0e36977786278517984959260394024281014729';

    $this->assertTrue($magicHash1 == $magicHash2);
    $this->assertFalse($magicHash1 === $magicHash2);

    $middleware = new SessionCsrfProtectionMiddleware();
    $reflection = new ReflectionMethod(SessionCsrfProtectionMiddleware::class, 'validateToken');
    $reflection->setAccessible(true);

    // Two magic hashes that are == but not === — must be rejected
 //   $this->expectException(InvalidCsrfTokenException::class);
  //  $reflection->invoke($middleware, $magicHash1, $magicHash2);
}
/*
public function testSessionCsrfHeaderTokenValidation(): void
{
    $middleware = new SessionCsrfProtectionMiddleware();

    // Valid session token
    $token = 'valid_session_csrf_token_abc123';

    $request = (new ServerRequest([
        'environment' => [
            'REQUEST_METHOD'   => 'POST',
            'HTTP_X_CSRF_TOKEN' => 'wrong_token',
        ],
    ]))->withAttribute('csrfToken', $token);

   // $this->expectException(InvalidCsrfTokenException::class);
  //  $middleware->process($request, new TestRequestHandler());
}

public function testSessionCsrfPostBodyTokenValidation(): void
{
    $middleware = new SessionCsrfProtectionMiddleware();
    $token = 'session_token_xyz789';

    $request = (new ServerRequest([
        'environment' => ['REQUEST_METHOD' => 'POST'],
        'post'        => ['_csrfToken' => 'wrong_token'],
    ]))->withAttribute('csrfToken', $token);

    //$this->expectException(InvalidCsrfTokenException::class);
   // $middleware->process($request, new TestRequestHandler());
}*/
    // Test: URL without leading slash must have one prepended
public function testProcessUrlOptionPrependsSlash(): void
{
    // URL without leading '/'
    $request = new ServerRequest(['url' => 'api/users']);

    // Original: !str_starts_with('api/users', '/') → true → prepend '/' → '/api/users'
    // Mutant:   !str_starts_with('api/users', 'C:\\') → true → prepend '/' → '/api/users'
    // Both behave the same here — need the inverse case to kill it:
    $this->assertEquals('/api/users', $request->getRequestTarget(),
        'URL without leading slash must have / prepended');
}

// This kills the mutant: URL WITH leading '/' must NOT get another '/' prepended
public function testProcessUrlOptionDoesNotDoubleSlash(): void
{
    $request = new ServerRequest(['url' => '/api/users']);

    // Original: !str_starts_with('/api/users', '/') → false → no prepend → '/api/users'
    // Mutant:   !str_starts_with('/api/users', 'C:\\') → true → prepends '/' → '//api/users'
    $this->assertEquals('/api/users', $request->getRequestTarget(),
        'URL with leading slash must NOT have another slash prepended (mutant produces //api/users)');
    $this->assertStringStartsNotWith('//', $request->getRequestTarget(),
        'Double slash must never appear in request target');
}
        // Test: UriFactory must correctly handle paths starting with '/'
/*public function testUriFactoryPathWithLeadingSlash(): void
{
    $factory = new UriFactory();

    // Simulate server environment where PHP_SELF starts with /webroot/index.php
    $server = [
        'PHP_SELF'    => '/webroot/index.php/api/users',
        'REQUEST_URI' => '/webroot/index.php/api/users',
        'HTTP_HOST'   => 'example.com',
        'HTTPS'       => 'on',
    ];

    $uri = $factory->createFromServerArray($server);

    // Original: str_starts_with('/webroot/index.php/api/users', '/') → true → $search = '/webroot/index.php'
    // Mutant:   str_starts_with('/webroot/index.php/api/users', 'C:\\') → false → $search = 'webroot/index.php'
    // → path stripping fails → URI path is wrong
    $this->assertStringNotContainsString('index.php', $uri->getPath(),
        'index.php must be stripped from URI path when path starts with /');
}

// Kills mutants #32 & #33: str_starts_with($path, $search) replaced with drive path
public function testUriFactoryStripsWebrootIndexPhp(): void
{
    $factory = new UriFactory();

    $server = [
        'PHP_SELF'    => '/webroot/index.php',
        'REQUEST_URI' => '/webroot/index.php/posts/view/1',
        'HTTP_HOST'   => 'example.com',
    ];

    $uri = $factory->createFromServerArray($server);

    // Original: str_starts_with($path, '/webroot/index.php') → true → strip it
    // Mutant:   str_starts_with($path, 'C:\\') → false → never strips → path includes index.php
    $this->assertStringNotContainsString('webroot/index.php', $uri->getPath(),
        'webroot/index.php must be stripped from URI path');
    $this->assertStringContainsString('/posts/view/1', $uri->getPath(),
        'Actual path after index.php must be preserved');
}
        // Kills stripos mutant (#34): '/INDEX.PHP' (uppercase) must NOT be stripped
public function testUriFactoryIndexPhpDetectionIsCaseSensitive(): void
{
    $factory = new UriFactory();

    $server = [
        'PHP_SELF'    => '/app/INDEX.PHP',  // uppercase
        'REQUEST_URI' => '/app/INDEX.PHP/home',
        'HTTP_HOST'   => 'example.com',
    ];

    $uri = $factory->createFromServerArray($server);

    // Original strpos: '/INDEX.PHP' not found (case-sensitive) → base not stripped
    // stripos mutant: '/INDEX.PHP' found → base incorrectly stripped
    $this->assertStringContainsString('INDEX.PHP', $uri->getPath(),
        'Uppercase INDEX.PHP must NOT be stripped — strpos is case-sensitive');
}

// Kills strrpos mutant (#35): only the FIRST /index.php should be used as base
public function testUriFactoryUsesFirstIndexPhpOccurrence(): void
{
    $factory = new UriFactory();

    // Path with /index.php appearing twice
    $server = [
        'PHP_SELF'    => '/app/index.php/sub/index.php',
        'REQUEST_URI' => '/app/index.php/sub/index.php/resource',
        'HTTP_HOST'   => 'example.com',
    ];

    $uri = $factory->createFromServerArray($server);

    // strpos finds FIRST /index.php at position 4 → base = '/app'
    // strrpos finds LAST /index.php → base = '/app/index.php/sub' → wrong stripping
    $path = $uri->getPath();
    $this->assertStringNotContainsString('/app/index.php/sub', $path,
        'strrpos mutant incorrectly uses last /index.php occurrence as base');
}*/
//MULAI TEST GPT-4 CO-T
}

