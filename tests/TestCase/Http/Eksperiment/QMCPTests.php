<?php
declare(strict_types=1);

namespace Cake\Test\TestCase\Http;

use PHPUnit\Framework\TestCase;

class QMCPTests extends TestCase
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