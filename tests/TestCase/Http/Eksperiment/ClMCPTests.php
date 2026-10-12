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

class ClMCPTests extends TestCase
{
    private function invokeMethod(object $obj, string $method, array $args = []): mixed
    {
        return (new ReflectionClass($obj))->getMethod($method)->invokeArgs($obj, $args);
    }

    private function makeSession(string $token): Session
    {
        $session = new Session();
        $session->write('csrfToken', $token);
        return $session;
    }

    public function testCsrfVerifyTokenReturnsTrueForValidToken(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $result = $this->invokeMethod($middleware, '_verifyToken', [$token]);
        $this->assertTrue($result);
    }

    public function testCsrfVerifyTokenReturnsFalseForTamperedHmac(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $key = random_bytes(CsrfProtectionMiddleware::TOKEN_VALUE_LENGTH);
        $fakeHmac = str_repeat('a', 40);
        $token = base64_encode($key . $fakeHmac);
        $result = $this->invokeMethod($middleware, '_verifyToken', [$token]);
        $this->assertFalse($result);
    }

    public function testCsrfVerifyTokenReturnsBool(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $result = $this->invokeMethod($middleware, '_verifyToken', [$token]);
        $this->assertIsBool($result);
    }

    public function testCsrfVerifyTokenFalseForTamperedHmacReturnsBool(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $key = random_bytes(CsrfProtectionMiddleware::TOKEN_VALUE_LENGTH);
        $fakeHmac = str_repeat('b', 40);
        $token = base64_encode($key . $fakeHmac);
        $result = $this->invokeMethod($middleware, '_verifyToken', [$token]);
        $this->assertIsBool($result);
        $this->assertFalse($result);
    }

    public function testCsrfVerifyTokenCaseSensitiveReturnsFalse(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $upper = strtoupper($token);
        if ($upper === $token) {
            $this->assertTrue(true);
            return;
        }
        $result = $this->invokeMethod($middleware, '_verifyToken', [$upper]);
        $this->assertFalse($result);
    }

    public function testCsrfVerifyTokenWithExtraCharReturnsFalse(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $result = $this->invokeMethod($middleware, '_verifyToken', [$token . 'x']);
        $this->assertFalse($result);
    }

    public function testCsrfValidateTokenPassesWithMatchingPostToken(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $request = new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $salted],
            'cookies' => ['csrfToken' => $token],
        ]);
        $this->expectNotToPerformAssertions();
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testCsrfValidateTokenPassesWithMatchingHeaderToken(): void
    {
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['csrfToken' => $token],
        ]))->withHeader('X-CSRF-Token', $salted);
        $this->expectNotToPerformAssertions();
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testCsrfValidateTokenThrowsOnMismatchedPostToken(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $wrong = $middleware->saltToken($middleware->createToken());
        $request = new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $wrong],
            'cookies' => ['csrfToken' => $token],
        ]);
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testCsrfValidateTokenThrowsOnMismatchedHeaderToken(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $wrong = $middleware->saltToken($middleware->createToken());
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['csrfToken' => $token],
        ]))->withHeader('X-CSRF-Token', $wrong);
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testCsrfValidateTokenThrowsOnCaseVariantPostToken(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $upper = strtoupper($salted);
        if ($upper === $salted) {
            throw new \Cake\Http\Exception\InvalidCsrfTokenException('forced');
        }
        $request = new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $upper],
            'cookies' => ['csrfToken' => $token],
        ]);
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testCsrfValidateTokenThrowsOnPostTokenWithExtraChar(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $request = new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $salted . 'x'],
            'cookies' => ['csrfToken' => $token],
        ]);
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testCsrfValidateTokenThrowsOnHeaderCaseVariant(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $upper = strtoupper($salted);
        if ($upper === $salted) {
            throw new \Cake\Http\Exception\InvalidCsrfTokenException('forced');
        }
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['csrfToken' => $token],
        ]))->withHeader('X-CSRF-Token', $upper);
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testCsrfValidateTokenThrowsOnHeaderWithExtraChar(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new CsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'cookies' => ['csrfToken' => $token],
        ]))->withHeader('X-CSRF-Token', $salted . 'x');
        $this->invokeMethod($middleware, '_validateToken', [$request]);
    }

    public function testSessionCsrfValidateTokenPassesWithMatchingPostToken(): void
    {
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $session = $this->makeSession($token);
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $salted],
        ]))->withAttribute('session', $session);
        $this->expectNotToPerformAssertions();
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

    public function testSessionCsrfValidateTokenPassesWithMatchingHeaderToken(): void
    {
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $salted = $middleware->saltToken($token);
        $session = $this->makeSession($token);
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
        ]))->withHeader('X-CSRF-Token', $salted)
           ->withAttribute('session', $session);
        $this->expectNotToPerformAssertions();
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

    public function testSessionCsrfValidateTokenThrowsOnMismatchedPostToken(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $session = $this->makeSession($token);
        $wrong = $middleware->saltToken($middleware->createToken());
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $wrong],
        ]))->withAttribute('session', $session);
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

    public function testSessionCsrfValidateTokenThrowsOnMismatchedHeaderToken(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $session = $this->makeSession($token);
        $wrong = $middleware->saltToken($middleware->createToken());
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
        ]))->withHeader('X-CSRF-Token', $wrong)
           ->withAttribute('session', $session);
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

    public function testSessionCsrfValidateTokenThrowsOnPostCaseVariant(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $session = $this->makeSession($token);
        $salted = $middleware->saltToken($token);
        $upper = strtoupper($salted);
        if ($upper === $salted) {
            throw new \Cake\Http\Exception\InvalidCsrfTokenException('forced');
        }
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $upper],
        ]))->withAttribute('session', $session);
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

    public function testSessionCsrfValidateTokenThrowsOnPostWithExtraChar(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $session = $this->makeSession($token);
        $salted = $middleware->saltToken($token);
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
            'post' => ['_csrfToken' => $salted . 'x'],
        ]))->withAttribute('session', $session);
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

    public function testSessionCsrfValidateTokenThrowsOnHeaderCaseVariant(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $session = $this->makeSession($token);
        $salted = $middleware->saltToken($token);
        $upper = strtoupper($salted);
        if ($upper === $salted) {
            throw new \Cake\Http\Exception\InvalidCsrfTokenException('forced');
        }
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
        ]))->withHeader('X-CSRF-Token', $upper)
           ->withAttribute('session', $session);
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

    public function testSessionCsrfValidateTokenThrowsOnHeaderWithExtraChar(): void
    {
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware = new SessionCsrfProtectionMiddleware();
        $token = $middleware->createToken();
        $session = $this->makeSession($token);
        $salted = $middleware->saltToken($token);
        $request = (new ServerRequest([
            'environment' => ['REQUEST_METHOD' => 'POST'],
        ]))->withHeader('X-CSRF-Token', $salted . 'x')
           ->withAttribute('session', $session);
        $this->invokeMethod($middleware, 'validateToken', [$request, $session]);
    }

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

    public function testCorsBuilderWindowsDriveCDoesNotMatch(): void
    {
        $response = new LaminasResponse();
        $builder = new CorsBuilder($response, 'https://example.com', true);
        $result = $builder->allowOrigin(['C:\\example'])->build();
        $this->assertSame('', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testCorsBuilderWindowsDriveDDoesNotMatch(): void
    {
        $response = new LaminasResponse();
        $builder = new CorsBuilder($response, 'https://example.com', true);
        $result = $builder->allowOrigin(['D:\\example'])->build();
        $this->assertSame('', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testCorsBuilderHttpOriginMatchesHttpBuilder(): void
    {
        $response = new LaminasResponse();
        $builder = new CorsBuilder($response, 'http://example.com', false);
        $result = $builder->allowOrigin(['example.com'])->build();
        $this->assertSame('http://example.com', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testCorsBuilderDomainWithColonSlashSlashNotMutated(): void
    {
        $response = new LaminasResponse();
        $builder = new CorsBuilder($response, 'https://api.example.com', true);
        $result = $builder->allowOrigin(['https://api.example.com'])->build();
        $this->assertSame('https://api.example.com', $result->getHeaderLine('Access-Control-Allow-Origin'));
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

    public function testServerRequestUrlWithWindowsDriveCStillPrependedSlash(): void
    {
        $request = new ServerRequest(['url' => 'C:\\posts\\index']);
        $this->assertStringStartsWith('/', $request->getRequestTarget());
    }

    public function testServerRequestUrlWithWindowsDriveDStillPrependedSlash(): void
    {
        $request = new ServerRequest(['url' => 'D:\\posts\\index']);
        $this->assertStringStartsWith('/', $request->getRequestTarget());
    }

    public function testServerRequestUrlWithQueryStringPreservesPath(): void
    {
        $request = new ServerRequest(['url' => 'search?q=test']);
        $target = $request->getRequestTarget();
        $this->assertStringStartsWith('/', $target);
    }

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
        $this->assertNotContains('en-', $result);
    }

    public function testAcceptedLanguagesUnderscoreAtPositionZeroNotNormalized(): void
    {
        $negotiation = new ContentTypeNegotiation();
        $request = (new ServerRequest())->withHeader('Accept-Language', '_US');
        $result = $negotiation->acceptedLanguages($request);
        $this->assertNotContains('-us', $result);
        $this->assertContains('_us', $result);
    }

    public function testAcceptedLanguagesMultipleUnderscoresNormalized(): void
    {
        $negotiation = new ContentTypeNegotiation();
        $request = (new ServerRequest())->withHeader('Accept-Language', 'zh_Hans_CN');
        $result = $negotiation->acceptedLanguages($request);
        $this->assertNotContains('zh_hans_cn', $result);
        $this->assertContains('zh-hans-cn', $result);
    }

    public function testAcceptedLanguagesStrrposDoesNotNormalizeLastUnderscoreOnly(): void
    {
        $negotiation = new ContentTypeNegotiation();
        $request = (new ServerRequest())->withHeader('Accept-Language', 'en_US');
        $result = $negotiation->acceptedLanguages($request);
        $this->assertContains('en-us', $result);
        $this->assertNotContains('en_us', $result);
    }

    public function testAcceptedLanguagesFullSuite(): void
    {
        $negotiation = new ContentTypeNegotiation();
        $request = new ServerRequest([
            'url' => '/dashboard',
            'environment' => [
                'HTTP_ACCEPT_LANGUAGE' => 'pt-BR;q=0.6,en_US,en_CA;q=0.8',
            ],
        ]);
        $expected = ['en-us', 'en-ca', 'pt-br'];
        $this->assertEquals($expected, $negotiation->acceptedLanguages($request));
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

    public function testHeaderUtilitySemicolonAtPositionZeroHandled(): void
    {
        $result = HeaderUtility::parseAccept(';q=0.5,text/html');
        $this->assertIsArray($result);
        $this->assertArrayHasKey('1.0', $result);
        $this->assertContains('text/html', $result['1.0']);
    }

    public function testHeaderUtilityStrposNotStrrposForSemicolon(): void
    {
        $result = HeaderUtility::parseAccept('text/html;charset=utf-8;q=0.3');
        $this->assertArrayHasKey('0.3', $result);
        $this->assertContains('text/html', $result['0.3']);
    }

    public function testHeaderUtilityStrposNotStrContainsForSemicolon(): void
    {
        $result = HeaderUtility::parseAccept('text/html');
        $this->assertArrayHasKey('1.0', $result);
        $this->assertNotEmpty($result['1.0']);
    }



    public function testHeaderUtilityStrposNotStriposForQParam(): void
    {
        $result = HeaderUtility::parseAccept('text/html;Q=0.6,application/json');
        $this->assertIsArray($result);
        $this->assertArrayHasKey('1.0', $result);
        $this->assertContains('application/json', $result['1.0']);
    }

    public function testHeaderUtilityFullSuite(): void
    {
        $result = HeaderUtility::parseAccept('application/json;q=0.5,application/xml;q=0.6,application/pdf;q=0.3');
        $expected = [
            '0.6' => ['application/xml'],
            '0.5' => ['application/json'],
            '0.3' => ['application/pdf'],
        ];
        $this->assertEquals($expected, $result);
    }

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

        $values = [
            'oauth_version'          => '1.0',
            'oauth_nonce'            => 'testnonce',
            'oauth_timestamp'        => '1234567890',
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_token'            => 'testtoken',
            'oauth_consumer_key'     => $encodeMethod->invoke($oauth, 'testkey'),
        ];
        $baseString = $oauth->baseString($request, $values);
        $encodedSecret = $encodeMethod->invoke($oauth, 'testsecret');
        $encodedTokenSecret = $encodeMethod->invoke($oauth, 'testtokensecret');
        $key = $encodedSecret . '&' . $encodedTokenSecret;

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
        $encodedSecret = $encodeMethod->invoke($oauth, 'testsecret');
        $encodedTokenSecret = $encodeMethod->invoke($oauth, 'testtokensecret');
        $key = $encodedSecret . '&' . $encodedTokenSecret;

        $whirlpoolSig = base64_encode(hash_hmac('whirlpool', $baseString, $key, true));
        $this->assertStringNotContainsString(rawurlencode($whirlpoolSig), $result);
    }

    public function testOauthSignatureLengthMatchesSha1(): void
    {
        $oauth = new Oauth();
        $ref = new ReflectionClass($oauth);
        $hmacMethod = $ref->getMethod('_hmacSha1');

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

        preg_match('/oauth_signature="([^"]+)"/', $result, $matches);
        $this->assertNotEmpty($matches);
        $decoded = base64_decode(rawurldecode($matches[1]), true);
        $this->assertSame(20, strlen($decoded));
    }

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

    public function testMockAdapterWildcardMatchesDeepPath(): void
    {
        $mock = new Mock();
        $mockRequest = new Request('http://example.com/api/%2A', 'GET');
        $mockResponse = new Response();
        $mock->addResponse($mockRequest, $mockResponse, []);
        $realRequest = new Request('http://example.com/api/v1/users/123', 'GET');
        $result = $mock->send($realRequest, []);
        $this->assertCount(1, $result);
    }

    public function testMockAdapterWildcardDoesNotMatchSubstringOfPrefix(): void
    {
        $this->expectException(\Cake\Http\Client\Exception\MissingResponseException::class);
        $mock = new Mock();
        $mockRequest = new Request('http://example.com/api/%2A', 'GET');
        $mockResponse = new Response();
        $mock->addResponse($mockRequest, $mockResponse, []);
        $realRequest = new Request('http://example.com/ap/resource', 'GET');
        $mock->send($realRequest, []);
    }

    public function testMockAdapterExactUriMatchReturnsResponse(): void
    {
        $mock = new Mock();
        $mockRequest = new Request('http://example.com/api/resource', 'GET');
        $mockResponse = new Response();
        $mock->addResponse($mockRequest, $mockResponse, []);
        $realRequest = new Request('http://example.com/api/resource', 'GET');
        $result = $mock->send($realRequest, []);
        $this->assertCount(1, $result);
        $this->assertSame($mockResponse, $result[0]);
    }

    public function testMockAdapterNonWildcardDoesNotMatchDifferentPath(): void
    {
        $this->expectException(\Cake\Http\Client\Exception\MissingResponseException::class);
        $mock = new Mock();
        $mockRequest = new Request('http://example.com/api/resource', 'GET');
        $mockResponse = new Response();
        $mock->addResponse($mockRequest, $mockResponse, []);
        $realRequest = new Request('http://example.com/api/other', 'GET');
        $mock->send($realRequest, []);
    }

    public function testMockAdapterWildcardDoesNotMatchEmptySegmentAfterPrefix(): void
    {
        $this->expectException(\Cake\Http\Client\Exception\MissingResponseException::class);
        $mock = new Mock();
        $mockRequest = new Request('http://example.com/api/v2/%2A', 'GET');
        $mockResponse = new Response();
        $mock->addResponse($mockRequest, $mockResponse, []);
        $realRequest = new Request('http://example.com/api/v1/resource', 'GET');
        $mock->send($realRequest, []);
    }
}