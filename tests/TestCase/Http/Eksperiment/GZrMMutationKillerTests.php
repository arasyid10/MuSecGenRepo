<? 
use PHPUnit\Framework\TestCase;
use Cake\Http\Client\Adapter\Mock;
use Cake\Http\Client\Auth\Oauth;
use Cake\Http\ContentTypeNegotiation;
use Cake\Http\CorsBuilder;
use Cake\Http\HeaderUtility;
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\ServerRequest;
use Cake\Http\UriFactory;
use Cake\TestSuite\TestCase as CakeTestCase;

class GZrMMutationKillerTests extends TestCase
{
    public function testMockAdapterStarPosition()
    {
        $mock = new Mock();
        $ref = new \ReflectionMethod($mock, 'matches');
        $ref->setAccessible(true);

        $mockUri = 'http://api.test/%2A';
        $requestUriMatch = 'http://api.test/actual/path';
        $requestUriFail = 'http://other.domain/path';

        $this->assertTrue($ref->invoke($mock, $mockUri, $requestUriMatch));
        $this->assertFalse($ref->invoke($mock, $mockUri, $requestUriFail));
    }

    public function testOauthSignatureHashing()
    {
        $oauth = new Oauth();
        $ref = new \ReflectionMethod($oauth, '_signature');
        $ref->setAccessible(true);

        $credentials = ['consumerSecret' => 'secret', 'tokenSecret' => 'token'];
        $baseString = 'base_string';
        $values = [];

        $result = $ref->invoke($oauth, $values, 'HMAC-SHA1', $credentials, $baseString);
        
        $key = 'secret&token';
        $expected = base64_encode(hash_hmac('sha1', $baseString, $key, true));
        $this->assertEquals($expected, $result['oauth_signature']);
        $this->assertNotEquals(base64_encode(hash_hmac('md5', $baseString, $key, true)), $result['oauth_signature']);
    }

    public function testContentTypeNegotiationUnderscore()
    {
        $negotiation = new ContentTypeNegotiation();
        $ref = new \ReflectionMethod($negotiation, 'parseAccept');
        $ref->setAccessible(true);

        $input = ['language' => ['en_US', 'FR_FR']];
        $result = $ref->invoke($negotiation, $input);
        
        $this->assertEquals('en-us', $result[0]);
    }

    public function testCorsBuilderDomainProtocol()
    {
        $builder = new CorsBuilder(new \Cake\Http\Response(), 'example.com', false);
        $ref = new \ReflectionMethod($builder, '_normalizeDomains');
        $ref->setAccessible(true);

        $domains = ['example.com'];
        $result = $ref->invoke($builder, $domains);
        $this->assertStringContainsString('http://example.com', $result[0][1]);
    }

    public function testHeaderUtilityParsing()
    {
        $headers = 'text/html; q=0.8; Q=0.9';
        $result = HeaderUtility::parseAccept($headers);
        
        $this->assertArrayHasKey('text/html', $result);
        $this->assertEquals('0.8', $result['text/html']);
    }

    public function testCsrfMiddlewareTimingAttackResistance()
    {
        $middleware = new CsrfProtectionMiddleware();
        $ref = new \ReflectionMethod($middleware, 'checkToken');
        $ref->setAccessible(true);

        $token = bin2hex(random_bytes(16));
        $salt = \Cake\Utility\Security::getSalt();
        $hmac = hash_hmac('sha1', $token, $salt);
        $fullToken = base64_encode($token . $hmac);

        $this->assertTrue($ref->invoke($middleware, $fullToken));
    }

    public function testServerRequestUrlProcessing()
    {
        $request = new ServerRequest();
        $ref = new \ReflectionMethod($request, 'processUrlOption');
        $ref->setAccessible(true);

        $config = ['url' => 'some/path'];
        $result = $ref->invoke($request, $config);
        $this->assertEquals('/some/path', $result['url']);
    }

    public function testUriFactoryIndexHandling()
    {
        $factory = new UriFactory();
        $ref = new \ReflectionMethod($factory, 'getWebrootPath');
        $ref->setAccessible(true);

        $server = ['PHP_SELF' => '/subdir/index.php/extra'];
        $path = '/subdir/webroot/index.php';
        
        $result = $ref->invoke($factory, $server, $path);
        $this->assertEquals('/', $result);
    }
}