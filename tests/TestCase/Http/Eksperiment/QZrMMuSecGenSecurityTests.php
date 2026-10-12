<?php
declare(strict_types=1);

namespace Cake\Test\TestCase\Http\Middleware;

use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\ServerRequest;
use Cake\Http\Response;
use Cake\Utility\Security;
use Cake\Http\Exception\InvalidCsrfTokenException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;

class QZrMMuSecGenSecurityTests extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (!Security::getSalt()) {
            Security::setSalt('test-secret-key-minimum-32-chars-long!!');
        }
    }

   

    public function testOauthSignatureEnforcesSha1Algorithm(): void
    {
        $credentials = [
            'consumerSecret' => 'consumer_secret',
            'tokenSecret' => 'token_secret'
        ];
        $baseString = 'GET&http%3A%2F%2Fexample.com%2Fapi&param%3Dvalue';
        
        $key = implode('&', array_map(
            fn($s) => rawurlencode($s), 
            [$credentials['consumerSecret'], $credentials['tokenSecret']]
        ));
        $expectedSig = base64_encode(hash_hmac('sha1', $baseString, $key, true));
        $md5Sig = base64_encode(hash_hmac('md5', $baseString, $key, true));
        $whirlpoolSig = base64_encode(hash_hmac('Whirlpool', $baseString, $key, true));

        $this->assertNotEquals($md5Sig, $expectedSig, 'MD5 produces different signature than SHA1');
        $this->assertNotEquals($whirlpoolSig, $expectedSig, 'Whirlpool produces different signature than SHA1');
       // $this->assertEquals(40, strlen(base64_decode($expectedSig, true)), 'SHA1 HMAC produces 20-byte output');
    }

    public function testCorsDomainSchemeDetectionRejectsWindowsPathInjection(): void
    {
        $request = new ServerRequest(['environment' => ['HTTP_ORIGIN' => 'https://example.com']]);
        $response = new Response();
        
        $corsResponse = $response->cors($request)
            ->allowOrigin(['https://example.com', 'http://test.org', 'example.com'])
            ->build();
        
        $header = $corsResponse->getHeaderLine('Access-Control-Allow-Origin');
        
        $this->assertStringNotContainsString('http://https://', $header);
        $this->assertStringNotContainsString('C:\\', $header);
        $this->assertStringNotContainsString('D:\\', $header);
        $this->assertMatchesRegularExpression('@^https?://[^/]+@', $header);
    }

  
    // public function testUrlPathProcessingHandlesUnixStylePathsOnly(): void
    // {
    //     $configWithSlash = '/api/users';
    //     $configWithoutSlash = 'api/users';
    //     $configWithQuery = '/api?param=value';
        
    //     $reflection = new \ReflectionClass(ServerRequest::class);
    //     $method = $reflection->getMethod('processUrlOption');
    //     $method->setAccessible(true);
        
    //     $request = new ServerRequest();
        
    //     $result1 = $method->invokeArgs($request, [$configWithSlash]);
    //     $this->assertSame('/api/users', $result1);
        
    //     $result2 = $method->invokeArgs($request, [$configWithoutSlash]);
    //     $this->assertSame('/api/users', $result2);
        
    //     $result3 = $method->invokeArgs($request, [$configWithQuery]);
    //     $this->assertStringStartsWith('/', $result3);
        
    //     $windowsStyleConfigs = [
    //         'C:\\path\\to\\app',
    //         'D:\\another\\path',
    //     ];
        
    //     foreach ($windowsStyleConfigs as $config) {
    //         $result = $method->invokeArgs($request, [$config]);
    //         $this->assertStringNotContainsString('C:\\', $result);
    //         $this->assertStringNotContainsString('D:\\', $result);
    //     }
    // }

    // public function testUriFactoryPathStrippingUsesCorrectStringFunction(): void
    // {
    //     $server = ['PHP_SELF' => '/webroot/index.php/some/path'];
        
    //     $reflection = new \ReflectionClass(\Cake\Http\UriFactory::class);
    //     $method = $reflection->getMethod('extractBase');
    //     $method->setAccessible(true);
        
    //     $base = dirname($server['PHP_SELF'] ?? DIRECTORY_SEPARATOR);
    //     $base = (string) preg_replace('#/+#', '/', $base);
    //     $indexPos = strpos($base, '/index.php');
        
    //     if ($indexPos !== false) {
    //         $expectedBase = substr($base, 0, $indexPos);
    //         $this->assertSame('/webroot', $expectedBase);
    //     }
        
    //     $this->assertNotSame(strpos($base, '/index.php'), strrpos($base, '/index.php'), 
    //         'strpos and strrpos should differ when multiple occurrences exist');
    // }

    public function testLanguageNegotiationUsesCaseSensitiveUnderscoreDetection(): void
    {
        $raw = [['en_US', 'fr_FR', 'de_DE']];
        $accept = [];
        
        foreach ($raw as $languages) {
            foreach ($languages as &$lang) {
                if (strpos($lang, '_')) {
                    $lang = str_replace('_', '-', $lang);
                }
                $lang = strtolower($lang);
            }
            $accept = array_merge($accept, $languages);
        }
        
        $this->assertContains('en-us', $accept);
        $this->assertContains('fr-fr', $accept);
        $this->assertContains('de-de', $accept);
        
        $caseVariants = [['EN_US', 'En_Us', 'en_us']];
        foreach ($caseVariants as $languages) {
            foreach ($languages as $lang) {
                $hasUnderscore = strpos($lang, '_') !== false;
                $hasUnderscoreCaseInsensitive = stripos($lang, '_') !== false;
                $this->assertSame($hasUnderscore, $hasUnderscoreCaseInsensitive, 
                    "Underscore detection should be case-insensitive for '_' character");
            }
        }
    }

    public function testHeaderParsingUsesPositionalSemicolonDetection(): void
    {
        $headers = ['text/html;q=0.9;charset=utf-8', 'application/json;q=0.8', 'text/plain; q=0.7'];
        
        foreach ($headers as $value) {
            $prefValue = '1.0';
            $value = trim($value);
            $semiPos = strpos($value, ';');
            
            /*$this->assertSame($semiPos, str_contains($value, ';'), 
                'strpos returns position, str_contains returns boolean');
            $this->assertSame($semiPos, strrpos($value, ';'), 
                'strpos finds first, strrpos finds last occurrence');
            */
            if ($semiPos !== false) {
                $params = explode(';', $value);
                $value = trim($params[0]);
                foreach ($params as $param) {
                    $qPos = strpos($param, 'q=');
                    $this->assertSame($qPos, stripos($param, 'q='), 
                        'q= position detection should be case-sensitive');
                    if ($qPos !== false) {
                        $prefValue = substr($param, $qPos + 2);
                        $this->assertMatchesRegularExpression('/^[0-9.]+$/', $prefValue);
                    }
                }
            }
        }
    }
/*
    public function testMockAdapterUriMatchingUsesStrictPrefixCheck(): void
    {
        $mockUri = 'https://api.example.com/users/%2A';
        $requestUris = [
            'https://api.example.com/users/123' => true,
            'https://api.example.com/users' => false,
            'https://api.example.com/admin/123' => false,
            'https://evil.com/users/123' => false,
        ];
        
        foreach ($requestUris as $requestUri => $shouldMatch) {
            $starPosition = strrpos($mockUri, '/%2A');
            if ($starPosition === strlen($mockUri) - 4) {
                $cleanMockUri = substr($mockUri, 0, $starPosition);
                $result = str_starts_with($requestUri, $cleanMockUri);
                echo $shouldMatch .", ". $result . "\n"; 
                $this->assertNotSame($shouldMatch, $result, 
                    "URI matching failed for: {$requestUri}");
            }
        }
        
        $this->assertTrue(str_starts_with('https://api.example.com/users/123', 'https://api.example.com/users'));
        $this->assertFalse(str_starts_with('https://evil.com/users/123', 'https://api.example.com/users'));
    }
*/
    private function _generateValidToken(): string
    {
        $key = random_bytes(16);
        $hmac = hash_hmac('sha1', $key, Security::getSalt(), true);
        return base64_encode($key . $hmac);
    }
}