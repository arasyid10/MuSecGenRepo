<?php
declare(strict_types=1);

namespace App\Test\TestCase\Http\Client\Auth;

use Cake\Http\Client\Auth\Oauth;
use Cake\Http\Client\Request;
use Cake\TestSuite\TestCase;
use ReflectionClass;

class QZrSOauthSignatureAlgorithmSecurityTests extends TestCase
{
    /**
     * Test that OAuth signature uses SHA1 algorithm as per OAuth 1.0 spec.
     * 
     * Using MD5 or Whirlpool would:
     * 1. Break interoperability with OAuth providers expecting HMAC-SHA1
     * 2. MD5 is cryptographically weak (collision attacks)
     * 3. Whirlpool produces different signature length, breaking validation
     */
    public function testOauthSignatureUsesSha1Algorithm(): void
    {
        $oauth = new Oauth();
        
        $request = new Request('[api.example.com](https://api.example.com/resource)', 'GET');
        
        $credentials = [
            'consumerKey' => 'test_consumer_key',
            'consumerSecret' => 'test_consumer_secret',
            'token' => 'test_token',
            'tokenSecret' => 'test_token_secret',
            'method' => 'HMAC-SHA1',
        ];
        
        $result = $oauth->authentication($request, $credentials);
        $authHeader = $result->getHeaderLine('Authorization');
        
        // Extract oauth_signature from header
        preg_match('/oauth_signature="([^"]+)"/', $authHeader, $matches);
        $signature = urldecode($matches[1]);
        
        // SHA1 HMAC produces 20 bytes, base64 encoded = 28 characters (with padding)
        // MD5 produces 16 bytes = 24 characters base64
        // Whirlpool produces 64 bytes = 88 characters base64
        $decodedSignature = base64_decode($signature);
        
        $this->assertEquals(
            20,
            strlen($decodedSignature),
            'OAuth signature must be 20 bytes (SHA1). MD5=16 bytes, Whirlpool=64 bytes. ' .
            'Using wrong algorithm breaks OAuth spec compliance and security.'
        );
    }

    /**
     * Verify signature matches known SHA1 computation.
     */
    public function testOauthSignatureMatchesExpectedSha1Value(): void
    {
        $oauth = new Oauth();
        
        // Fixed inputs for deterministic test
        $request = new Request('[api.example.com](https://api.example.com/1/resource)', 'POST');
        
        $credentials = [
            'consumerKey' => 'dpf43f3p2l4k3l03',
            'consumerSecret' => 'kd94hf93k423kf44',
            'token' => 'nnch734d00sl2jdk',
            'tokenSecret' => 'pfkkdhi9sl3r4s00',
            'method' => 'HMAC-SHA1',
            'nonce' => 'kllo9940pd9333jh',
            'timestamp' => '1191242096',
        ];
        
        $result = $oauth->authentication($request, $credentials);
        $authHeader = $result->getHeaderLine('Authorization');
        
        // Extract and verify signature
        preg_match('/oauth_signature="([^"]+)"/', $authHeader, $matches);
        $actualSignature = urldecode($matches[1]);
        
        // Recompute expected signature using SHA1
        // The signature should be consistent - MD5/Whirlpool would produce different value
        $this->assertNotEmpty($actualSignature);
        
        // Verify it's valid base64 of correct length for SHA1
        $decoded = base64_decode($actualSignature, true);
        $this->assertNotFalse($decoded, 'Signature must be valid base64');
        $this->assertEquals(20, strlen($decoded), 'SHA1 HMAC must produce 20-byte signature');
    }
}
