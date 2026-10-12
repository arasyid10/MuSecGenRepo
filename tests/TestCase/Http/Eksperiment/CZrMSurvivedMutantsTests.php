<?php

declare(strict_types=1);

namespace Cake\Test\TestCase\Http;

use Cake\Http\Client\Adapter\Mock;
use Cake\Http\Client\Auth\Oauth;
use Cake\Http\Client\Request;
use Cake\Http\Client\Response;
use Cake\Http\ContentTypeNegotiation;
use Cake\Http\CorsBuilder;
use Cake\Http\HeaderUtility;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\ServerRequest;
use Cake\Http\Session;
use Laminas\Diactoros\Response as LaminasResponse;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class CZrMSurvivedMutantsTests extends TestCase
{
    // =========================================================
    // PRIORITY 1: HashEqualsToInsecureEqualityMutator (#18-#27)
    // =========================================================

    public function testCsrfVerifyTokenReturnsTrueForValidToken(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('_verifyToken');

        $token = $middleware->createToken();
        $result = $method->invoke($middleware, $token);
        $this->assertTrue($result);
    }

    public function testCsrfVerifyTokenReturnsFalseForTamperedHmac(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('_verifyToken');

        $key = random_bytes(CsrfProtectionMiddleware::TOKEN_VALUE_LENGTH);
        $fakeHmac = str_repeat('a', 40);
        $token = base64_encode($key . $fakeHmac);

        $result = $method->invoke($middleware, $token);
        $this->assertFalse($result);
    }

    public function testCsrfValidateTokenPassesWithMatchingPostToken(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $saltedToken = $middleware->saltToken($token);

        $request = new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $saltedToken],
            'cookies' => ['csrfToken' => $token],
        ]);

        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('_validateToken');

        $this->expectNotToPerformAssertions();
        $method->invoke($middleware, $request);
    }

    public function testCsrfValidateTokenPassesWithMatchingHeaderToken(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $saltedToken = $middleware->saltToken($token);

        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['csrfToken' => $token],
        ]))->withHeader('X-CSRF-Token', $saltedToken);

        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('_validateToken');

        $this->expectNotToPerformAssertions();
        $method->invoke($middleware, $request);
    }

    public function testCsrfValidateTokenThrowsOnMismatchedPostToken(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);

        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $wrongToken = $middleware->createToken();
        $saltedWrong = $middleware->saltToken($wrongToken);

        $request = new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $saltedWrong],
            'cookies' => ['csrfToken' => $token],
        ]);

        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('_validateToken');
        $method->invoke($middleware, $request);
    }

    public function testCsrfValidateTokenThrowsOnMismatchedHeaderToken(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);

        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $wrongToken = $middleware->createToken();
        $saltedWrong = $middleware->saltToken($wrongToken);

        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['csrfToken' => $token],
        ]))->withHeader('X-CSRF-Token', $saltedWrong);

        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('_validateToken');
        $method->invoke($middleware, $request);
    }

    private function makeSessionWithToken(string $token): Session
    {
        $session = new Session();
        $session->write('csrfToken', $token);
        return $session;
    }

    public function testSessionCsrfValidateTokenPassesWithMatchingPostToken(): void
    {
        $middleware = new SessionCsrfProtectionMiddleware();
        $rawToken = $middleware->createToken();
        $salted = $middleware->saltToken($rawToken);
        $session = $this->makeSessionWithToken($rawToken);

        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $salted],
        ]))->withAttribute('session', $session);

        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('validateToken');

        $this->expectNotToPerformAssertions();
        $method->invoke($middleware, $request, $session);
    }

    public function testSessionCsrfValidateTokenPassesWithMatchingHeaderToken(): void
    {
        $middleware = new SessionCsrfProtectionMiddleware();
        $rawToken = $middleware->createToken();
        $salted = $middleware->saltToken($rawToken);
        $session = $this->makeSessionWithToken($rawToken);

        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
        ]))->withHeader('X-CSRF-Token', $salted)
           ->withAttribute('session', $session);

        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('validateToken');

        $this->expectNotToPerformAssertions();
        $method->invoke($middleware, $request, $session);
    }

    public function testSessionCsrfValidateTokenThrowsOnMismatch(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);

        $middleware = new SessionCsrfProtectionMiddleware();
        $rawToken = $middleware->createToken();
        $session = $this->makeSessionWithToken($rawToken);

        $wrongToken = $middleware->createToken();
        $saltedWrong = $middleware->saltToken($wrongToken);

        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $saltedWrong],
        ]))->withAttribute('session', $session);

        $ref = new ReflectionClass($middleware);
        $method = $ref->getMethod('validateToken');
        $method->invoke($middleware, $request, $session);
    }

    // =========================================================
    // PRIORITY 2: ReplaceSecondArgWithDriveMutator (#9,#10,#28,#29,#30-#33)
    // =========================================================

    public function testCorsBuilderDomainWithoutProtocolGetsPrepended(): void
    {
        $response = new LaminasResponse();
        $builder = new CorsBuilder($response, 'https://example.com', true);
        $result = $builder->allowOrigin(['example.com'])->build();

        $this->assertSame('https://example.com', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testCorsBuilderDomainWithProtocolMatchesDirectly(): void
    {
        $response = new LaminasResponse();
        $builder = new CorsBuilder($response, 'https://example.com', true);
        $result = $builder->allowOrigin(['https://example.com'])->build();

        $this->assertSame('https://example.com', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testCorsBuilderDomainWithDrivePathDoesNotMatch(): void
    {
        $response = new LaminasResponse();
        $builder = new CorsBuilder($response, 'https://example.com', true);
        $result = $builder->allowOrigin(['C:\\example'])->build();

        $this->assertSame('', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testServerRequestUrlWithoutLeadingSlashGetsPrepended(): void
    {
        $request = new ServerRequest(['url' => 'posts/index']);
        $this->assertStringStartsWith('/', $request->getRequestTarget());
    }

    public function testServerRequestUrlWithLeadingSlashUnchanged(): void
    {
        $request = new ServerRequest(['url' => '/posts/index']);
        $this->assertSame('/posts/index', $request->getRequestTarget());
    }

    // =========================================================
    // PRIORITY 3: StrposToStriposMutator / StrposToStrrposMutator (#4,#6,#11,#13,#16,#17,#34,#35)
    // =========================================================

    public function testAcceptedLanguagesNormalizesUnderscoreToHyphen(): void
    {
        $negotiation = new ContentTypeNegotiation();
        $request = (new ServerRequest())->withHeader('Accept-Language', 'en_US,fr_FR;q=0.9');
        $result = $negotiation->acceptedLanguages($request);

        $this->assertContains('en-us', $result);
        $this->assertContains('fr-fr', $result);
    }

    public function testAcceptedLanguagesWithoutUnderscoreUnchanged(): void
    {
        $negotiation = new ContentTypeNegotiation();
        $request = (new ServerRequest())->withHeader('Accept-Language', 'en,fr;q=0.9');
        $result = $negotiation->acceptedLanguages($request);

        $this->assertContains('en', $result);
    }

    public function testHeaderUtilityParsesQValueCorrectly(): void
    {
        $result = HeaderUtility::parseAccept('text/html;q=0.8,application/json');

        $this->assertArrayHasKey('0.8', $result);
        $this->assertContains('text/html', $result['0.8']);
        $this->assertArrayHasKey('1.0', $result);
        $this->assertContains('application/json', $result['1.0']);
    }

    public function testHeaderUtilityNoSemicolonDefaultsToOnePointZero(): void
    {
        $result = HeaderUtility::parseAccept('text/html');

        $this->assertArrayHasKey('1.0', $result);
        $this->assertContains('text/html', $result['1.0']);
    }

    public function testHeaderUtilityMultipleQValues(): void
    {
        $result = HeaderUtility::parseAccept('text/html;q=0.9,application/json;q=0.5');

        $this->assertArrayHasKey('0.9', $result);
        $this->assertArrayHasKey('0.5', $result);
        $this->assertContains('text/html', $result['0.9']);
        $this->assertContains('application/json', $result['0.5']);
    }

    public function testHeaderUtilityQValueExtractedFromCorrectPosition(): void
    {
        $result = HeaderUtility::parseAccept('text/html;charset=utf-8;q=0.7');

        $this->assertArrayHasKey('0.7', $result);
        $this->assertContains('text/html', $result['0.7']);
    }

    // =========================================================
    // PRIORITY 4: StrposToStrContainsMutator / StrposToStrstrMutator /
    //             StrposToStrpbrkMutator (#5,#7,#8,#12,#14,#15)
    // strpos('_US','_')===0 is falsy → underscore at pos 0 is NOT normalized
    // str_contains/strstr/strpbrk return truthy → mutant WOULD normalize it
    // Test must assert original behavior: NOT normalized when '_' is at pos 0
    // =========================================================

    public function testAcceptedLanguagesUnderscoreAtPositionZeroNotNormalized(): void
    {
        $negotiation = new ContentTypeNegotiation();
        $request = (new ServerRequest())->withHeader('Accept-Language', '_US');
        $result = $negotiation->acceptedLanguages($request);

        $this->assertNotContains('-us', $result);
        $this->assertContains('_us', $result);
    }

    public function testHeaderUtilitySemicolonAtPositionZeroHandled(): void
    {
        $result = HeaderUtility::parseAccept(';q=0.5,text/html');

        $this->assertIsArray($result);
        $this->assertArrayHasKey('1.0', $result);
        $this->assertContains('text/html', $result['1.0']);
    }

    // =========================================================
    // PRIORITY 4: HashHmacAlgoAlternativesMutator (#2,#3)
    // =========================================================

    public function testOauthSignatureUsesSha1NotMd5(): void
    {
        $oauth = new Oauth();
        $ref = new ReflectionClass($oauth);
        $hmacMethod = $ref->getMethod('_hmacSha1');
        $encodeMethod = $ref->getMethod('_encode');

        $credentials = [
            'consumerKey'    => 'testkey',
            'consumerSecret' => 'testsecret',
            'token'          => 'testtoken',
            'tokenSecret'    => 'testtokensecret',
            'nonce'          => 'testnonce',
            'timestamp'      => '1234567890',
        ];

        $request = new Request('http://example.com/api', 'GET');
        $result = $hmacMethod->invoke($oauth, $request, $credentials);

        $this->assertStringContainsString('oauth_signature="', $result);

        $values = [
            'oauth_version'          => '1.0',
            'oauth_nonce'            => 'testnonce',
            'oauth_timestamp'        => '1234567890',
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_token'            => 'testtoken',
            'oauth_consumer_key'     => $encodeMethod->invoke($oauth, 'testkey'),
        ];
        $baseString = $oauth->baseString($request, $values);
        $key = implode('&', array_map('rawurlencode', ['testsecret', 'testtokensecret']));

        $expectedSha1 = base64_encode(hash_hmac('sha1', $baseString, $key, true));
        $expectedMd5  = base64_encode(hash_hmac('md5', $baseString, $key, true));

        $this->assertStringContainsString(rawurlencode($expectedSha1), $result);
        $this->assertStringNotContainsString(rawurlencode($expectedMd5), $result);
    }

    public function testOauthSignatureNotWhirlpool(): void
    {
        $oauth = new Oauth();
        $ref = new ReflectionClass($oauth);
        $hmacMethod = $ref->getMethod('_hmacSha1');
        $encodeMethod = $ref->getMethod('_encode');

        $credentials = [
            'consumerKey'    => 'testkey',
            'consumerSecret' => 'testsecret',
            'token'          => 'testtoken',
            'tokenSecret'    => 'testtokensecret',
            'nonce'          => 'testnonce',
            'timestamp'      => '1234567890',
        ];

        $request = new Request('http://example.com/api', 'GET');
        $result = $hmacMethod->invoke($oauth, $request, $credentials);

        $values = [
            'oauth_version'          => '1.0',
            'oauth_nonce'            => 'testnonce',
            'oauth_timestamp'        => '1234567890',
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_token'            => 'testtoken',
            'oauth_consumer_key'     => $encodeMethod->invoke($oauth, 'testkey'),
        ];
        $baseString = $oauth->baseString($request, $values);
        $key = implode('&', array_map('rawurlencode', ['testsecret', 'testtokensecret']));

        $whirlpoolSig = base64_encode(hash_hmac('whirlpool', $baseString, $key, true));
        $this->assertStringNotContainsString(rawurlencode($whirlpoolSig), $result);
    }

    // =========================================================
    // PRIORITY 5: ReturnConstantTrueMutator (#1)
    // =========================================================

    public function testMockAdapterWildcardUriMatchesSamePrefix(): void
    {
        $mock = new Mock();
        $mockRequest = new Request('http://example.com/api/%2A', 'GET');
        $mockResponse = new Response();
        $mock->addResponse($mockRequest, $mockResponse, []);

        $realRequest = new Request('http://example.com/api/resource', 'GET');
        $result = $mock->send($realRequest, []);

        $this->assertCount(1, $result);
        $this->assertSame($mockResponse, $result[0]);
    }

    public function testMockAdapterWildcardUriDoesNotMatchDifferentPrefix(): void
    {
        $this->expectException(\Cake\Http\Client\Exception\MissingResponseException::class);

        $mock = new Mock();
        $mockRequest = new Request('http://example.com/api/%2A', 'GET');
        $mockResponse = new Response();
        $mock->addResponse($mockRequest, $mockResponse, []);

        $realRequest = new Request('http://other.com/api/resource', 'GET');
        $mock->send($realRequest, []);
    }
}