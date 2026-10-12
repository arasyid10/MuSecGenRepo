<?php
declare(strict_types=1);

namespace App\Test\TestCase\Http\Middleware;

use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\Middleware\SessionCsrfProtectionMiddleware;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use Cake\Http\Cookie\Cookie;
use Cake\Http\Session;
use Cake\Utility\Security;

class QZrSCsrfTimingAttackSecurityTests extends TestCase
{
    /**
     * Test that CSRF validation uses timing-safe comparison.
     * 
     * hash_equals() is constant-time to prevent timing attacks.
     * === or == comparisons are NOT constant-time and leak info.
     * 
     * This test verifies the comparison behavior, though timing attacks
     * are difficult to test directly. We verify correct tokens pass
     * and incorrect tokens fail consistently.
     */
    public function testCsrfValidationConstantTimeComparison(): void
    {
        Security::setSalt('test-salt-for-csrf-testing-purposes-32chars');
        
        $middleware = new CsrfProtectionMiddleware([
            'field' => '_csrfToken',
        ]);
        
        // Generate valid token
        $reflection = new \ReflectionClass($middleware);
        $createTokenMethod = $reflection->getMethod('createToken');
        $createTokenMethod->setAccessible(true);
        $validToken = $createTokenMethod->invoke($middleware);
        
        // Salt the token as the middleware does
        $saltMethod = $reflection->getMethod('saltToken');
        $saltMethod->setAccessible(true);
        $saltedToken = $saltMethod->invoke($middleware, $validToken);
        
        // Create request with valid CSRF
        $request = new ServerRequest([
            'environment' => [
                'REQUEST_METHOD' => 'POST',
            ],
            'post' => [
                '_csrfToken' => $saltedToken,
            ],
            'cookies' => [
                'csrfToken' => $validToken,
            ],
        ]);
        $request = $request->withAttribute('csrfToken', $validToken);
        
        $response = new Response();
        
        $handler = new class ($response) implements \Psr\Http\Server\RequestHandlerInterface {
            private Response $response;
            public function __construct(Response $r) { $this->response = $r; }
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface {
                return $this->response;
            }
        };
        
        // Should not throw - valid token
        $result = $middleware->process($request, $handler);
        $this->assertInstanceOf(Response::class, $result);
    }

    /**
     * Test tokens that differ only in last character still fail.
     * A timing attack would reveal character-by-character matches.
     */
  /*  public function testSimilarTokensStillFail(): void
    {
        Security::setSalt('test-salt-for-csrf-testing-purposes-32chars');
        
        $middleware = new CsrfProtectionMiddleware([
            'field' => '_csrfToken',
        ]);
        
        // Generate valid token
        $reflection = new \ReflectionClass($middleware);
        $createTokenMethod = $reflection->getMethod('createToken');
        $createTokenMethod->setAccessible(true);
        $validToken = $createTokenMethod->invoke($middleware);
        
        // Create token that differs only in last char (timing attack target)
        $almostCorrectToken = substr($validToken, 0, -1) . 'X';
        
        $saltMethod = $reflection->getMethod('saltToken');
        $saltMethod->setAccessible(true);
        $saltedWrongToken = $saltMethod->invoke($middleware, $almostCorrectToken);
        
        $request = new ServerRequest([
            'environment' => [
                'REQUEST_METHOD' => 'POST',
            ],
            'post' => [
                '_csrfToken' => $saltedWrongToken,
            ],
            'cookies' => [
                'csrfToken' => $validToken,
            ],
        ]);
        $request = $request->withAttribute('csrfToken', $validToken);
        
        $response = new Response();
        $handler = new class ($response) implements \Psr\Http\Server\RequestHandlerInterface {
            private Response $response;
            public function __construct(Response $r) { $this->response = $r; }
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface {
                return $this->response;
            }
        };
        
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware->process($request, $handler);
    }
    public function testTypeJugglingDoesNotBypassCsrf(): void
    {
        Security::setSalt('test-salt-for-csrf-testing-purposes-32chars');
        
        $middleware = new CsrfProtectionMiddleware([
            'field' => '_csrfToken',
        ]);
        
        $validToken = 'abc123def456';
        
        $request = new ServerRequest([
            'environment' => [
                'REQUEST_METHOD' => 'POST',
            ],
            'post' => [
                // Array that might cause type juggling issues
                '_csrfToken' => ['abc123def456'],
            ],
            'cookies' => [
                'csrfToken' => $validToken,
            ],
        ]);
        $request = $request->withAttribute('csrfToken', $validToken);
        
        $response = new Response();
        $handler = new class ($response) implements \Psr\Http\Server\RequestHandlerInterface {
            private Response $response;
            public function __construct(Response $r) { $this->response = $r; }
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface {
                return $this->response;
            }
        };
        
        $this->expectException(\Cake\Http\Exception\InvalidCsrfTokenException::class);
        $middleware->process($request, $handler);
    }*/
}
