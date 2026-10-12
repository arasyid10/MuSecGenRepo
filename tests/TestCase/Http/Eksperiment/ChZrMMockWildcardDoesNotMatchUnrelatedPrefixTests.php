<?php
declare(strict_types=1);

namespace Cake\Test\TestCase\Http\Eksperiment;

use Cake\Http\Client\Adapter\Mock;
use Cake\Http\Client\Auth\Oauth;
use Cake\Http\Client\Exception\MissingResponseException;
use Cake\Http\Client\Request;
use Cake\Http\Client\Response as ClientResponse;
use Cake\Http\CorsBuilder;
use Cake\Http\Exception\InvalidCsrfTokenException;
use Cake\Http\HeaderUtility;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\Http\Session;
use Cake\TestSuite\TestCase;
use Psr\Http\Message\ServerRequestInterface;

class ChZrMMockWildcardDoesNotMatchUnrelatedPrefixTests extends TestCase
{
    public function testMockWildcardDoesNotMatchUnrelatedPrefix(): void
    {
        $adapter = new Mock();

        $mockRequest = new Request('http://example.com/api/%2A', 'GET');
        $adapter->addResponse($mockRequest, new ClientResponse([], 'matched'), []);

        $request = new Request('http://example.com/other/resource', 'GET');

        $this->expectException(MissingResponseException::class);
        $adapter->send($request, []);
    }

    public function testMockWildcardMatchesOnlyExpectedPrefix(): void
    {
        $adapter = new Mock();

        $mockRequest = new Request('http://example.com/api/%2A', 'GET');
        $adapter->addResponse($mockRequest, new ClientResponse([], 'matched'), []);

        $request = new Request('http://example.com/api/users', 'GET');
        $responses = $adapter->send($request, []);

        $this->assertCount(1, $responses);
        $this->assertSame('matched', (string)$responses[0]->getBody());
    }

    public function testAcceptLanguageDoesNotNormalizeLeadingUnderscore(): void
    {
        $request = new ServerRequest([
            'environment' => [
                'HTTP_ACCEPT_LANGUAGE' => '__EN;q=0.9,en;q=0.1',
            ],
        ]);

        $this->assertSame(['__en', 'en'], $request->acceptLanguage());
    }

    public function testHeaderUtilityUsesCaseSensitiveLowercaseQualityParameter(): void
{
    $result = HeaderUtility::parseAccept('text/html;Q=0.2, application/json;q=0.8');

    $this->assertSame([
        '1.0' => ['text/html'],
        '0.8' => ['application/json'],
    ], $result);
}

    public function testCorsBuilderDoesNotPrefixDomainsThatAlreadyContainScheme(): void
    {
        $builder = new CorsBuilder(new Response(), 'http://example.com', false);

        $response = $builder
            ->allowOrigin(['http://example.com'])
            ->build();

        $this->assertSame(
            'http://example.com',
            $response->getHeaderLine('Access-Control-Allow-Origin')
        );
    }

    public function testServerRequestKeepsAbsolutePathWithSingleLeadingSlash(): void
    {
        $request = new ServerRequest([
            'url' => '/articles/view/1?published=1',
        ]);

        $this->assertSame('/articles/view/1', $request->getUri()->getPath());
        $this->assertSame('published=1', $request->getUri()->getQuery());
    }

    public function testServerRequestAddsSlashOnlyForRelativePath(): void
    {
        $request = new ServerRequest([
            'url' => 'articles/view/1',
        ]);

        $this->assertSame('/articles/view/1', $request->getUri()->getPath());
    }

    public function testOauthSignatureUsesHmacSha1(): void
    {
        $auth = new Oauth();

        $request = new Request(
            'https://example.com/resource?b=two&a=one',
            'POST',
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            'c=three'
        );

        $credentials = [
            'consumerKey' => 'consumer-key',
            'consumerSecret' => 'consumer-secret',
            'token' => 'token-key',
            'tokenSecret' => 'token-secret',
            'nonce' => 'fixed-nonce',
            'timestamp' => '1234567890',
        ];

        $request = $auth->authentication($request, $credentials);
        $header = $request->getHeaderLine('Authorization');

        $this->assertStringContainsString('oauth_signature_method="HMAC-SHA1"', $header);

        $expectedBaseString = implode('&', [
            rawurlencode('POST'),
            rawurlencode('https://example.com/resource'),
            rawurlencode('a=one&b=two&c=three&oauth_consumer_key=consumer-key&oauth_nonce=fixed-nonce&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1234567890&oauth_token=token-key&oauth_version=1.0'),
        ]);

        $expectedKey = rawurlencode('consumer-secret') . '&' . rawurlencode('token-secret');
        $expectedSignature = base64_encode(hash_hmac('sha1', $expectedBaseString, $expectedKey, true));

        $this->assertStringContainsString(
            'oauth_signature="' . rawurlencode($expectedSignature) . '"',
            $header
        );
    }

    public function testCookieCsrfRejectsLooseEqualPostToken(): void
    {
        $middleware = new class ([]) extends CsrfProtectionMiddleware {
            public function unsaltToken(string $token): string
            {
                return $token;
            }

            public function validateRequest(ServerRequestInterface $request): void
            {
                $this->_validateToken($request);
            }
        };

        $request = new ServerRequest([
            'post' => [
                '_csrfToken' => '0e22222',
            ],
            'cookies' => [
                'csrfToken' => '0e11111',
            ],
            'environment' => [
                'REQUEST_METHOD' => 'POST',
            ],
        ]);

        $this->expectException(InvalidCsrfTokenException::class);
        $middleware->validateRequest($request);
    }

    public function testCookieCsrfRejectsLooseEqualHeaderToken(): void
    {
        $middleware = new class ([]) extends CsrfProtectionMiddleware {
            public function unsaltToken(string $token): string
            {
                return $token;
            }

            public function validateRequest(ServerRequestInterface $request): void
            {
                $this->_validateToken($request);
            }
        };

        $request = new ServerRequest([
            'cookies' => [
                'csrfToken' => '0e11111',
            ],
            'environment' => [
                'REQUEST_METHOD' => 'POST',
                'HTTP_X_CSRF_TOKEN' => '0e22222',
            ],
        ]);

        $this->expectException(InvalidCsrfTokenException::class);
        $middleware->validateRequest($request);
    }

    public function testSessionCsrfRejectsLooseEqualPostToken(): void
    {
        $middleware = new class ([]) extends SessionCsrfProtectionMiddleware {
            public function validateRequest(ServerRequestInterface $request, Session $session): void
            {
                $this->validateToken($request, $session);
            }

            protected function unsaltToken(string $token): string
            {
                return $token;
            }
        };

        $session = new Session();
        $session->write('csrfToken', '0e11111');

        $request = new ServerRequest([
            'post' => [
                '_csrfToken' => '0e22222',
            ],
            'environment' => [
                'REQUEST_METHOD' => 'POST',
            ],
        ]);

        $this->expectException(InvalidCsrfTokenException::class);
        $middleware->validateRequest($request, $session);
    }

    public function testSessionCsrfRejectsLooseEqualHeaderToken(): void
    {
        $middleware = new class ([]) extends SessionCsrfProtectionMiddleware {
            public function validateRequest(ServerRequestInterface $request, Session $session): void
            {
                $this->validateToken($request, $session);
            }

            protected function unsaltToken(string $token): string
            {
                return $token;
            }
        };

        $session = new Session();
        $session->write('csrfToken', '0e11111');

        $request = new ServerRequest([
            'environment' => [
                'REQUEST_METHOD' => 'POST',
                'HTTP_X_CSRF_TOKEN' => '0e22222',
            ],
        ]);

        $this->expectException(InvalidCsrfTokenException::class);
        $middleware->validateRequest($request, $session);
    }
}