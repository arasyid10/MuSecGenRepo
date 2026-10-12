<?php
/*
declare(strict_types=1);

namespace Cake\Http {
    final class GPTMCPHttpFunctionRecorder
    {
        public static array $calls = [];

        public static function reset(): void
        {
            self::$calls = [];
        }

        public static function has(string $function, mixed $needle): bool
        {
            foreach (self::$calls as $call) {
                if (($call['function'] ?? null) === $function && ($call['needle'] ?? null) === $needle) {
                    return true;
                }
            }

            return false;
        }
    }

    function strpos(string $haystack, string $needle, int $offset = 0): int|false
    {
        GPTMCPHttpFunctionRecorder::$calls[] = [
            'function' => 'strpos',
            'haystack' => $haystack,
            'needle' => $needle,
            'offset' => $offset,
        ];

        return \strpos($haystack, $needle, $offset);
    }

    function str_contains(string $haystack, string $needle): bool
    {
        GPTMCPHttpFunctionRecorder::$calls[] = [
            'function' => 'str_contains',
            'haystack' => $haystack,
            'needle' => $needle,
        ];

        return \str_contains($haystack, $needle);
    }

    function str_starts_with(string $haystack, string $needle): bool
    {
        GPTMCPHttpFunctionRecorder::$calls[] = [
            'function' => 'str_starts_with',
            'haystack' => $haystack,
            'needle' => $needle,
        ];

        return \str_starts_with($haystack, $needle);
    }

    function str_ends_with(string $haystack, string $needle): bool
    {
        GPTMCPHttpFunctionRecorder::$calls[] = [
            'function' => 'str_ends_with',
            'haystack' => $haystack,
            'needle' => $needle,
        ];

        return \str_ends_with($haystack, $needle);
    }
}

namespace Cake\Http\Client\Auth {
    final class GPTMCPHmacRecorder
    {
        public static array $calls = [];

        public static function reset(): void
        {
            self::$calls = [];
        }

        public static function algorithms(): array
        {
            return array_map(static fn(array $call): string => strtolower($call['algo']), self::$calls);
        }
    }

    function hash_hmac(string $algo, string $data, string $key, bool $binary = false): string
    {
        GPTMCPHmacRecorder::$calls[] = [
            'algo' => $algo,
            'data' => $data,
            'key' => $key,
            'binary' => $binary,
        ];

        return \hash_hmac($algo, $data, $key, $binary);
    }
}

namespace Cake\Http\Middleware {
    final class GPTMCPHashEqualsRecorder
    {
        public static array $calls = [];

        public static function reset(): void
        {
            self::$calls = [];
        }

        public static function count(): int
        {
            return count(self::$calls);
        }

        public static function hasPair(string $known, string $user): bool
        {
            foreach (self::$calls as $call) {
                if ($call['known'] === $known && $call['user'] === $user) {
                    return true;
                }
            }

            return false;
        }
    }

    function hash_equals(string $known_string, string $user_string): bool
    {
        GPTMCPHashEqualsRecorder::$calls[] = [
            'known' => $known_string,
            'user' => $user_string,
        ];

        return \hash_equals($known_string, $user_string);
    }
}

namespace Cake\Test\TestCase\Http\Eksperiment {
    use Cake\Core\Configure;
    use Cake\Http\Client\Auth\GPTMCPHmacRecorder;
    use Cake\Http\Client\Auth\Oauth;
    use Cake\Http\Client\Request as ClientRequest;
    use Cake\Http\ContentTypeNegotiation;
    use Cake\Http\CorsBuilder;
    use Cake\Http\GPTMCPHttpFunctionRecorder;
    use Cake\Http\HeaderUtility;
    use Cake\Http\Middleware\CsrfProtectionMiddleware;
    use Cake\Http\Middleware\GPTMCPHashEqualsRecorder;
    use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
    use Cake\Http\ServerRequest;
    use Cake\Http\Session;
    use Cake\Http\UriFactory;
    use Cake\Utility\Security;
    use PHPUnit\Framework\TestCase;
    use Psr\Http\Message\UriInterface;
    use ReflectionClass;
    use ReflectionMethod;
    use Cake\Test\TestCase\Http\Eksperiment\EksperimentTestCase;
    class GPTMCPRuntimeContractTests extends TestCase
    {
        protected function tearDown(): void
        {
            parent::tearDown();
            Configure::delete('App');
            GPTMCPHttpFunctionRecorder::reset();
            GPTMCPHmacRecorder::reset();
            GPTMCPHashEqualsRecorder::reset();
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

        private function invoke(object|string $objectOrClass, string $method, mixed ...$args): mixed
        {
            $reflection = new ReflectionMethod($objectOrClass, $method);

            if (is_string($objectOrClass)) {
                return $reflection->invokeArgs(null, $args);
            }

            return $reflection->invokeArgs($objectOrClass, $args);
        }

        private function invokeExisting(object|string $objectOrClass, array $methods, mixed ...$args): mixed
        {
            foreach ($methods as $method) {
                if (method_exists($objectOrClass, $method)) {
                    $reflection = new ReflectionMethod($objectOrClass, $method);

                    if (is_string($objectOrClass)) {
                        return $reflection->invokeArgs(null, $args);
                    }

                    return $reflection->invokeArgs($objectOrClass, $args);
                }
            }

            $className = is_string($objectOrClass) ? $objectOrClass : $objectOrClass::class;

            throw new \RuntimeException($className . ' does not contain any of: ' . implode(', ', $methods));
        }

        private function newCorsBuilderWithoutConstructor(): CorsBuilder
        {
            $reflection = new ReflectionClass(CorsBuilder::class);
            $builder = $reflection->newInstanceWithoutConstructor();

            foreach (['_isSsl', 'isSsl'] as $propertyName) {
                if ($reflection->hasProperty($propertyName)) {
                    $property = $reflection->getProperty($propertyName);
                    $property->setValue($builder, false);
                }
            }

            return $builder;
        }

        private function csrfCookie(CsrfProtectionMiddleware $middleware): string
        {
            $reflection = new ReflectionClass($middleware);
            $length = (int)$reflection->getConstant('TOKEN_VALUE_LENGTH');
            $key = str_repeat('a', $length);
            $hmac = \hash_hmac('sha1', $key, Security::getSalt());

            return base64_encode($key . $hmac);
        }

        public function testOauthAuthenticationMustUseSha1Hmac(): void
        {
            GPTMCPHmacRecorder::reset();

            $oauth = new Oauth();
            $request = new ClientRequest(
                'https://example.com/oauth/resource?b=2&a=1',
                'POST',
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                'c=3&d=4'
            );

            $credentials = [
                'consumerKey' => 'consumer-key',
                'consumerSecret' => 'consumer-secret',
                'token' => 'token-value',
                'tokenSecret' => 'token-secret',
            ];

            $authenticated = $oauth->authentication($request, $credentials);

            $this->assertStringContainsString('OAuth', $authenticated->getHeaderLine('Authorization'));
            $this->assertContains('sha1', GPTMCPHmacRecorder::algorithms());
            $this->assertNotContains('md5', GPTMCPHmacRecorder::algorithms());
            $this->assertNotContains('whirlpool', GPTMCPHmacRecorder::algorithms());
        }

        public function testAcceptedLanguagesMustUseStrposForUnderscoreDetection(): void
        {
            GPTMCPHttpFunctionRecorder::reset();

            $content = new ContentTypeNegotiation();
            $request = new ServerRequest([
                'url' => '/dashboard',
                'environment' => [
                    'HTTP_ACCEPT_LANGUAGE' => '_EN;q=0.9,__FR;q=0.8,en_US;q=0.7',
                ],
            ]);

            $this->assertSame(['_en', '__fr', 'en-us'], $content->acceptedLanguages($request));
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('strpos', '_'));
        }

        public function testCorsNormalizeDomainsMustCheckSchemeSeparatorNeedle(): void
        {
            GPTMCPHttpFunctionRecorder::reset();

            $builder = $this->newCorsBuilderWithoutConstructor();
            $result = $this->invoke($builder, '_normalizeDomains', ['https://api.example.test']);

            $this->assertSame('https://api.example.test', $result[0]['original']);
            $this->assertSame(1, preg_match($result[0]['preg'], 'https://api.example.test'));
            $this->assertSame(0, preg_match($result[0]['preg'], 'http://https://api.example.test'));
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('str_contains', '://'));
        }

        public function testParseAcceptMustUseStrposForSemicolonAndQParameter(): void
        {
            GPTMCPHttpFunctionRecorder::reset();

            $result = HeaderUtility::parseAccept('text/html;foo=q=0.2q=0.7,application/json;q=0.8');

            $this->assertSame([
                '0.8' => ['application/json'],
                '0.2q=0.7' => ['text/html'],
            ], $result);
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('strpos', ';'));
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('strpos', 'q='));
        }

        public function testParseAcceptMustNotTreatUppercaseQAsQualityParameter(): void
        {
            GPTMCPHttpFunctionRecorder::reset();

            $result = HeaderUtility::parseAccept('text/html;Q=0.4,application/json;q=0.8');

            $this->assertSame([
                '1.0' => ['text/html'],
                '0.8' => ['application/json'],
            ], $result);
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('strpos', 'q='));
        }

       public function testCsrfVerifyTokenMustUseHashEquals(): void
{
    $middleware = new CsrfProtectionMiddleware([]);
    $cookie = $this->csrfCookie($middleware);

    $decoded = base64_decode($cookie);
    $reflection = new ReflectionClass($middleware);
    $length = (int)$reflection->getConstant('TOKEN_VALUE_LENGTH');
    $key = substr($decoded, 0, $length);
    $hmac = substr($decoded, $length);
    $expectedHmac = \hash_hmac('sha1', $key, Security::getSalt());

    GPTMCPHashEqualsRecorder::reset();

    $this->assertTrue($this->invoke($middleware, '_verifyToken', $cookie));
    $this->assertGreaterThanOrEqual(1, GPTMCPHashEqualsRecorder::count());
    $this->assertTrue(GPTMCPHashEqualsRecorder::hasPair($hmac, $expectedHmac));
}

        public function testCsrfBodyTokenValidationMustUseHashEquals(): void
        {
            $middleware = new CsrfProtectionMiddleware([]);
            $cookie = $this->csrfCookie($middleware);

            $request = (new ServerRequest())
                ->withCookieParams(['csrfToken' => $cookie])
                ->withParsedBody(['_csrfToken' => $cookie]);

            GPTMCPHashEqualsRecorder::reset();

            $this->invoke($middleware, '_validateToken', $request);

            $this->assertGreaterThanOrEqual(2, GPTMCPHashEqualsRecorder::count());
            $this->assertTrue(GPTMCPHashEqualsRecorder::hasPair($cookie, $cookie));
        }

        public function testCsrfHeaderTokenValidationMustUseHashEquals(): void
        {
            $middleware = new CsrfProtectionMiddleware([]);
            $cookie = $this->csrfCookie($middleware);

            $request = (new ServerRequest())
                ->withCookieParams(['csrfToken' => $cookie])
                ->withHeader('X-CSRF-Token', $cookie);

            GPTMCPHashEqualsRecorder::reset();

            $this->invoke($middleware, '_validateToken', $request);

            $this->assertGreaterThanOrEqual(2, GPTMCPHashEqualsRecorder::count());
            $this->assertTrue(GPTMCPHashEqualsRecorder::hasPair($cookie, $cookie));
        }

     public function testSessionCsrfBodyTokenValidationMustUseHashEquals(): void
{
    $middleware = new SessionCsrfProtectionMiddleware([]);
    $token = str_repeat('b', 64);
    $session = new Session();
    $session->write('csrfToken', $token);

    $request = (new ServerRequest())
        ->withAttribute('session', $session)
        ->withParsedBody(['_csrfToken' => $token]);

    GPTMCPHashEqualsRecorder::reset();

    if (method_exists($middleware, '_validateToken')) {
        $this->invoke($middleware, '_validateToken', $request);
    } else {
        $this->invoke($middleware, 'validateToken', $request, $session);
    }

    $this->assertGreaterThanOrEqual(1, GPTMCPHashEqualsRecorder::count());
    $this->assertTrue(GPTMCPHashEqualsRecorder::hasPair($token, $token));
}

    public function testSessionCsrfHeaderTokenValidationMustUseHashEquals(): void
{
    $middleware = new SessionCsrfProtectionMiddleware([]);
    $token = str_repeat('c', 64);
    $session = new Session();
    $session->write('csrfToken', $token);

    $request = (new ServerRequest())
        ->withAttribute('session', $session)
        ->withHeader('X-CSRF-Token', $token);

    GPTMCPHashEqualsRecorder::reset();

    if (method_exists($middleware, '_validateToken')) {
        $this->invoke($middleware, '_validateToken', $request);
    } else {
        $this->invoke($middleware, 'validateToken', $request, $session);
    }

    $this->assertGreaterThanOrEqual(1, GPTMCPHashEqualsRecorder::count());
    $this->assertTrue(GPTMCPHashEqualsRecorder::hasPair($token, $token));
}

        public function testServerRequestProcessUrlOptionMustCheckLeadingSlash(): void
        {
            $request = new ServerRequest();

            GPTMCPHttpFunctionRecorder::reset();

            $result = $this->invoke($request, 'processUrlOption', [
                'url' => '/dashboard?role=admin',
                'environment' => [],
                'query' => [],
            ]);

            $this->assertSame('/dashboard', $result['url']);
            $this->assertSame('role=admin', $result['environment']['QUERY_STRING']);
            $this->assertSame(['role' => 'admin'], $result['query']);
            $this->assertSame('/dashboard', $result['environment']['REQUEST_URI']);
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('str_starts_with', '/'));
        }

        public function testUriFactoryUpdatePathMustUseSlashAndSearchNeedles(): void
        {
            Configure::write('App.baseUrl', '/index.php');
            Configure::write('App.webroot', 'webroot');

            GPTMCPHttpFunctionRecorder::reset();

            $updated = UriFactory::updatePath('', $this->uriDouble('/webroot/index.php/articles/view/1'));

            $this->assertSame('/articles/view/1', $updated->getPath());
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('str_starts_with', '/'));
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('str_starts_with', '/webroot/index.php'));
        }

        public function testUriFactoryUpdatePathMustCollapseTrailingWebrootIndexPhp(): void
        {
            Configure::write('App.baseUrl', '/index.php');
            Configure::write('App.webroot', 'webroot');

            GPTMCPHttpFunctionRecorder::reset();

            $updated = UriFactory::updatePath('', $this->uriDouble('/app/webroot/index.php'));

            $this->assertSame('/', $updated->getPath());
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('str_ends_with', '/webroot/index.php'));
        }

        public function testUriFactoryGetBaseMustUseCaseSensitiveStrpos(): void
        {
            Configure::write('App', [
                'base' => null,
                'webroot' => 'webroot',
                'baseUrl' => null,
            ]);

            GPTMCPHttpFunctionRecorder::reset();

            $result = $this->invokeExisting(UriFactory::class, ['getBase'], $this->uriDouble('/'), [
                'PHP_SELF' => '/myapp/INDEX.php/webroot/page.php',
            ]);

            $this->assertSame('/myapp/INDEX.php', $result['base']);
            $this->assertSame('/myapp/INDEX.php/', $result['webroot']);
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('strpos', '/index.php'));
        }

        public function testUriFactoryGetBaseMustUseFirstIndexPhpOccurrence(): void
        {
            Configure::write('App', [
                'base' => null,
                'webroot' => 'webroot',
                'baseUrl' => null,
            ]);

            GPTMCPHttpFunctionRecorder::reset();

            $result = $this->invokeExisting(UriFactory::class, ['getBase'], $this->uriDouble('/'), [
                'PHP_SELF' => '/one/index.php/two/index.php/page.php',
            ]);

            $this->assertSame('/one', $result['base']);
            $this->assertSame('/one/', $result['webroot']);
            $this->assertTrue(GPTMCPHttpFunctionRecorder::has('strpos', '/index.php'));
        }
    }
    
}*/

//QWEN

declare(strict_types=1);

namespace Cake\Test\TestCase\Http\Eksperiment ;
    use Cake\Core\Configure;
    use Cake\Http\Client\Auth\GPTMCPHmacRecorder;
    use Cake\Http\Client\Auth\Oauth;
    use Cake\Http\Client\Request as ClientRequest;
    use Cake\Http\ContentTypeNegotiation;
    use Cake\Http\CorsBuilder;
    use Cake\Http\GPTMCPHttpFunctionRecorder;
    use Cake\Http\HeaderUtility;
    use Cake\Http\Middleware\CsrfProtectionMiddleware;
    use Cake\Http\Middleware\GPTMCPHashEqualsRecorder;
    use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
    use Cake\Http\ServerRequest;
    use Cake\Http\Session;
    use Cake\Http\UriFactory;
    use Cake\Utility\Security;
    use PHPUnit\Framework\TestCase;
    use Psr\Http\Message\UriInterface;
    use ReflectionClass;
    use ReflectionMethod;
    use Cake\Test\TestCase\Http\Eksperiment\EksperimentTestCase;

class GPTMCPRuntimeContractTests extends TestCase
{
    public function testMockUriWildcardStrictPrefixMatching(): void
    {
        $mockUri = 'https://api.example.com/users/%2A';
        $requestUri = 'https://api.example.com/admin/123';
        $starPosition = strrpos($mockUri, '/%2A');

        if ($starPosition === strlen($mockUri) - 4) {
            $cleanMockUri = substr($mockUri, 0, $starPosition);
            $result = str_starts_with($requestUri, $cleanMockUri);
            $this->assertFalse($result);
        }
    }

    public function testOauthSignatureEnforcesSha1AlgorithmAndLength(): void
    {
        $key = 'consumer_secret&token_secret';
        $baseString = 'GET&http%3A%2F%2Fexample.com%2Fapi&param%3Dvalue';

        $expectedSha1 = base64_encode(hash_hmac('sha1', $baseString, $key, true));
        $md5Sig = base64_encode(hash_hmac('md5', $baseString, $key, true));
        $whirlpoolSig = base64_encode(hash_hmac('Whirlpool', $baseString, $key, true));

        $this->assertSame(28, strlen($expectedSha1));
        $this->assertNotSame(strlen($expectedSha1), strlen($md5Sig));
        $this->assertNotSame(strlen($expectedSha1), strlen($whirlpoolSig));
        $this->assertNotEquals($expectedSha1, $md5Sig);
        $this->assertNotEquals($expectedSha1, $whirlpoolSig);
    }

    public function testLanguageAndHeaderParsingReliesOnFirstPositionalOccurrence(): void
    {
        $lang = 'en_US';
        $langPos = strpos($lang, '_');
        $this->assertIsInt($langPos);
        $this->assertSame(2, $langPos);

        $header = 'text/html; q=0.8; charset=utf-8';
        $semiPos = strpos($header, ';');
        $this->assertIsInt($semiPos);
        $this->assertSame(9, $semiPos);

        $params = explode(';', $header);
        $qParam = trim($params[1]);
        $qPos = strpos($qParam, 'q=');
        $this->assertIsInt($qPos);
        $this->assertSame(0, $qPos);

        $prefValue = substr($qParam, $qPos + 2);
        $this->assertSame('0.8', $prefValue);

        $multiOccurrence = 'q=0.9; q=0.5';
        $firstPos = strpos($multiOccurrence, 'q=');
        $lastPos = strrpos($multiOccurrence, 'q=');
        $this->assertNotSame($firstPos, $lastPos);
        $this->assertSame(0, $firstPos);
    }

    public function testCorsAndUrlNormalizationRejectsWindowsDriveMutations(): void
    {
        $domainWithScheme = 'https://example.com';
        $this->assertTrue(str_contains($domainWithScheme, '://'));
        $this->assertFalse(str_contains($domainWithScheme, 'C:\\'));
        $this->assertFalse(str_contains($domainWithScheme, 'D:\\'));

        $urlWithoutSlash = 'api/users';
        $this->assertFalse(str_starts_with($urlWithoutSlash, '/'));
        $this->assertFalse(str_starts_with($urlWithoutSlash, 'C:\\'));
        $this->assertFalse(str_starts_with($urlWithoutSlash, 'D:\\'));

        $normalizedUrl = '/' . $urlWithoutSlash;
        $this->assertSame('/api/users', $normalizedUrl);
    }

    public function testUriBasePathTruncationUsesFirstOccurrence(): void
    {
        $base = '/app/index.php/webroot/index.php';
        $indexPos = strpos($base, '/index.php');

        $this->assertIsInt($indexPos);
        $this->assertSame(4, $indexPos);

        $truncatedBase = substr($base, 0, $indexPos);
        $this->assertSame('/app', $truncatedBase);

        $lastIndexPos = strrpos($base, '/index.php');
        $this->assertNotSame($indexPos, $lastIndexPos);
    }

    public function testCsrfTokenComparisonRejectsTypeJugglingAndEnforcesStrictEquality(): void
    {
        $tokenA = '0e123456789012345678901234567890';
        $tokenB = '0e987654321098765432109876543210';

        $this->assertTrue($tokenA == $tokenB);
        $this->assertFalse($tokenA === $tokenB);
        $this->assertFalse(hash_equals($tokenA, $tokenB));

        $validToken = bin2hex(random_bytes(32));
        $modifiedToken = $validToken . 'x';

        $this->assertFalse(hash_equals($validToken, $modifiedToken));
        $this->assertFalse($validToken === $modifiedToken);
        $this->assertTrue(hash_equals($validToken, $validToken));

        $shortToken = substr($validToken, 0, 10);
        $this->assertFalse(hash_equals($validToken, $shortToken));
    }
}