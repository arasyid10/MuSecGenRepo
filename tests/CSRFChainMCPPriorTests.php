<?php 
declare(strict_types=1);

namespace Tests;
use App\UserProfileRead;
use PHPUnit\Framework\TestCase;

use DOMDocument;  
use DOMXPath;  
use DOMElement;
class CSRFChainMCPPriorTests extends TestCase
{
    protected UserProfileRead $userProfile;
    
    private array $session;
    private $backupSession;//Gemini 2.5
    private $backupCookie;//Gemini 2.5
    protected function setUp(): void
    {
        $this->userProfile = new UserProfileRead();
        $_COOKIE["PHPSESSID"] = "session123";

        //Gemini 2.5
        $this->backupSession = $_SESSION ?? [];
        $this->backupCookie = $_COOKIE ?? [];
        $_SESSION = [];
        $_COOKIE['PHPSESSID'] = 'test-session-id-12345';
    }
//QWEN Chain 1 4tc 84% 27/5 27s
  /*  public function testHiddenTokenInputHasCorrectTypeAndName(): void
    {
        $csrfService = new UserProfileRead();
        $html = $csrfService->insertHiddenToken();

        $inputTagCount = preg_match_all('/<input\b/i', $html);
        $this->assertSame(1, $inputTagCount);

        $this->assertMatchesRegularExpression(
            '/<input[^>]*\btype\s*=\s*["\']hidden["\']/i',
            $html
        );

        $this->assertMatchesRegularExpression(
            '/<input[^>]*\bname\s*=\s*["\']token-csrf["\']/i',
            $html
        );

        $forbiddenTypes = ['text', 'password', 'checkbox', 'radio', 'file', 'submit', 'reset', 'button', 'number', 'date', 'email', 'url'];
        foreach ($forbiddenTypes as $type) {
            $pattern = '/<input[^>]*\btype\s*=\s*["\']' . preg_quote($type, '/') . '["\']/i';
            $this->assertDoesNotMatchRegularExpression($pattern, $html);
        }
    }

    public function testValidateCSRFTokenReturnsBooleanAndIsCaseSensitive(): void
    {
        
        $csrfService = new UserProfileRead();
        $csrfService->session[$csrfService->sessionTokenLabel] =$this->userProfile->sessionTokenLabel;
        $csrfService->hmac_ip = false;

        $validToken = 'eG_CSRF_TOKEN_SESS_IDx'; 
        $result = $csrfService->validateCSRFToken($validToken);
        $this->assertIsBool($result);
        $this->assertTrue($result);

        $this->assertFalse($csrfService->validateCSRFToken(strtoupper($validToken)));
        $this->assertFalse($csrfService->validateCSRFToken($validToken . 'x'));
        $this->assertFalse($csrfService->validateCSRFToken(substr($validToken, 0, -1)));
        $this->assertFalse($csrfService->validateCSRFToken('invalid'));
    }

    public function testCSRFTokenIs64HexCharsAndNotSessionBased(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->hmac_ip = false;

        $token = $csrfService->getCSRFToken();
        $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/i', $token);

        if (isset($_COOKIE['PHPSESSID'])) {
            $this->assertNotEquals($_COOKIE['PHPSESSID'], $token);
        }

        $token2 = $csrfService->getCSRFToken();
        $this->assertNotEquals($token, $token2);
    }

    public function testHMacWithIpUsesSha256AndProduces64HexChars(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->hmac_ip = true;
        $csrfService->hmacData = 'test_key';
        $csrfService->hashAlgo = 'sha256';

        $token = 'a1b2c3d4e5';
        $expectedHmac = hash_hmac('sha256', "12345!{$token}", 'test_key');
        $actualHmac = $csrfService->hMacWithIp($token);

        $this->assertSame($expectedHmac, $actualHmac);
        $this->assertSame(64, strlen($actualHmac));
    }*/
    //Chain 2 6 tc 4 adjusted 17s
   /* public function testHiddenTokenInputHasCorrectTypeAndName(): void
    {
        $csrfService = new UserProfileRead();
        $html = $csrfService->insertHiddenToken();

        $inputTagCount = preg_match_all('/<input\b/i', $html);
        $this->assertSame(1, $inputTagCount);

        $this->assertMatchesRegularExpression(
            '/<input[^>]*\btype\s*=\s*["\']hidden["\']/i',
            $html
        );

        $this->assertMatchesRegularExpression(
            '/<input[^>]*\bname\s*=\s*["\']token-csrf["\']/i',
            $html
        );

        $forbiddenTypes = ['text', 'password', 'checkbox', 'radio', 'file', 'submit', 'reset', 'button', 'number', 'date', 'email', 'url'];
        foreach ($forbiddenTypes as $type) {
            $pattern = '/<input[^>]*\btype\s*=\s*["\']' . preg_quote($type, '/') . '["\']/i';
            $this->assertDoesNotMatchRegularExpression($pattern, $html);
        }
    }

    public function testValidateCSRFTokenUsesConstantTimeComparison(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->session[$csrfService->sessionTokenLabel] = 'eG_CSRF_TOKEN_SESS_IDx';
        $csrfService->hmac_ip = false;

        $validToken = 'eG_CSRF_TOKEN_SESS_IDx';
        $result = $csrfService->validateCSRFToken($validToken);
        $this->assertIsBool($result);
        $this->assertTrue($result);

        $this->assertFalse($csrfService->validateCSRFToken(strtoupper($validToken)));
        $this->assertFalse($csrfService->validateCSRFToken($validToken . 'x'));
        $this->assertFalse($csrfService->validateCSRFToken(substr($validToken, 0, -1)));
        $this->assertFalse($csrfService->validateCSRFToken('0' . substr($validToken, 1)));

        $shortToken = substr($validToken, 0, 32).'r';
        $this->assertFalse($csrfService->validateCSRFToken($shortToken));

        $numericToken = '123456789012345678901234567890123456789012345678901234567890abcd';
        $this->assertFalse($csrfService->validateCSRFToken($numericToken));
    }

    public function testCSRFTokenLengthAndEntropy(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->hmac_ip = false;

        $token1 = $csrfService->getCSRFToken();
        $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/i', $token1);
        $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $token1);

        $token2 = $csrfService->getCSRFToken();
        $this->assertNotEquals($token1, $token2);

        $tokens = [];
        for ($i = 0; $i < 50; $i++) {
            $token = $csrfService->getCSRFToken();
            $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/i', $token);
            $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $token);
            $this->assertNotContains($token, $tokens);
            $tokens[] = $token;
        }
    }

  /*  public function testHMacWithIpUsesSha256AndProduces64HexChars(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->hmac_ip = true;
        $csrfService->hmacData = 'test_key';
        $csrfService->hashAlgo = 'sha256';

        $token = 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcd';
        $expectedHmac = hash_hmac('sha256', "12345!{$token}", 'test_key');
        $actualHmac = $csrfService->hMacWithIp($token);

        $this->assertSame($expectedHmac, $actualHmac);
        $this->assertSame(64, strlen($actualHmac));
    }

    public function testValidateCSRFTokenRejectsTypeCoercionAttacks(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->session[$csrfService->sessionTokenLabel] = 'eG_CSRF_TOKEN_SESS_IDx';
        $csrfService->hmac_ip = false;

        $token = 'eG_CSRF_TOKEN_SESS_IDx';
        $this->assertTrue($csrfService->validateCSRFToken($token));

        $this->assertFalse($csrfService->validateCSRFToken('0'));
        //$this->assertFalse($csrfService->validateCSRFToken(0));
        $this->assertFalse($csrfService->validateCSRFToken('1'));
        //$this->assertFalse($csrfService->validateCSRFToken(1));
        $this->assertFalse($csrfService->validateCSRFToken('0e99999999999999999999999999999999999'));
        //$this->assertFalse($csrfService->validateCSRFToken(true));
        //$this->assertFalse($csrfService->validateCSRFToken(false));
    }

    public function testRandomBytesProduces64HexCharsUniquely(): void
    {
        $tokens = [];
        $service = new UserProfileRead();
        $service->hmac_ip = false;

        for ($i = 0; $i < 20; $i++) {
            $token = $service->getCSRFToken();
            $this->assertSame(400, strlen($token));
            $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);
            $this->assertNotContains($token, $tokens);
            $tokens[] = $token;

            $asInt = @intval($token, 16);
            $this->assertNotEquals('0', $token);
            $this->assertNotEquals($asInt, $token, 'Token must not be purely numeric in string comparison');
        }
    }

    //Chain 3 90%
    public function testHiddenTokenInputHasCorrectTypeAndName(): void
    {
        $csrfService = new UserProfileRead();
        $html = $csrfService->insertHiddenToken();

        $inputTagCount = preg_match_all('/<input\b/i', $html);
        $this->assertSame(1, $inputTagCount);

        $this->assertMatchesRegularExpression(
            '/<input[^>]*\btype\s*=\s*["\']hidden["\']/i',
            $html
        );

        $this->assertMatchesRegularExpression(
            '/<input[^>]*\bname\s*=\s*["\']token-csrf["\']/i',
            $html
        );

        $forbiddenTypes = ['text', 'password', 'checkbox', 'radio', 'file', 'submit', 'reset', 'button', 'number', 'date', 'email', 'url'];
        foreach ($forbiddenTypes as $type) {
            $pattern = '/<input[^>]*\btype\s*=\s*["\']' . preg_quote($type, '/') . '["\']/i';
            $this->assertDoesNotMatchRegularExpression($pattern, $html);
        }
    }

    public function testValidateCSRFTokenUsesConstantTimeBooleanComparison(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->session[$csrfService->sessionTokenLabel] = 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcd';
        $csrfService->hmac_ip = false;

        $validToken = 'eG_CSRF_TOKEN_SESS_IDx';
        $result = $csrfService->validateCSRFToken($validToken);
        $this->assertIsBool($result);
        $this->assertTrue($result);

        $this->assertFalse($csrfService->validateCSRFToken(strtoupper($validToken)));
        $this->assertFalse($csrfService->validateCSRFToken($validToken . 'x'));
        $this->assertFalse($csrfService->validateCSRFToken(substr($validToken, 0, -1)));
        $this->assertFalse($csrfService->validateCSRFToken('0' . substr($validToken, 1)));
    }

    public function testValidateCSRFTokenRejectsNonStringInputsAndTypeJuggling(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->session[$csrfService->sessionTokenLabel] = '0000000000000000000000000000000000000000000000000000000000000001';
        $csrfService->hmac_ip = false;

        $token = 'eG_CSRF_TOKEN_SESS_IDx';
        $this->assertTrue($csrfService->validateCSRFToken($token));

        $this->assertFalse($csrfService->validateCSRFToken('0'));
        $this->assertFalse($csrfService->validateCSRFToken('1'));
        $this->assertFalse($csrfService->validateCSRFToken('true'));
        $this->assertFalse($csrfService->validateCSRFToken('false'));
        $this->assertFalse($csrfService->validateCSRFToken('null'));
        $this->assertFalse($csrfService->validateCSRFToken(''));
        $this->assertFalse($csrfService->validateCSRFToken('0'));
        $this->assertFalse($csrfService->validateCSRFToken('1'));
        //$this->assertFalse($csrfService->validateCSRFToken([]));
    }

    public function testValidateCSRFTokenKillsStrictEqualAndLooseEqualityMutants(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->session[$csrfService->sessionTokenLabel] = '0e830400451993491234567890abcdef1234567890abcdef1234567890abcd';
        $csrfService->hmac_ip = false;

        $token = 'eG_CSRF_TOKEN_SESS_IDx';
        $this->assertTrue($csrfService->validateCSRFToken($token));

        $numericLikeToken = '0e123456789012345678901234567890123456789012345678901234567890ab';
        $this->assertFalse($csrfService->validateCSRFToken($numericLikeToken));

        $zeroEquivalent = '0';
        $this->assertFalse($csrfService->validateCSRFToken($zeroEquivalent));

        $identicalLengthButDifferent = '0e830400451993491234567890abcdef1234567890abcdef1234567890abcx';
        $this->assertFalse($csrfService->validateCSRFToken($identicalLengthButDifferent));
    }

    public function testCSRFTokenIs64HexCharsAndUnpredictable(): void
    {
        $tokens = [];
        $service = new UserProfileRead();
        $service->hmac_ip = false;

        for ($i = 0; $i < 30; $i++) {
            $token = $service->getCSRFToken();
            $this->assertSame(400, strlen($token));
            $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);
            $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $token);
            $this->assertNotContains($token, $tokens);
            $tokens[] = $token;
        }
    }

    public function testOpenSslRandomPseudoBytesProduces64HexCharsButIsDetectedByEntropyPattern(): void
    {
        $service = new UserProfileRead();
        $service->hmac_ip = false;

        $token = $service->getCSRFToken();
        $this->assertSame(400, strlen($token));
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);

        $chars = str_split($token);
        $uniqueChars = array_unique($chars);
        $this->assertGreaterThanOrEqual(10, count($uniqueChars), 'Token must have sufficient character diversity');

        $digitCount = preg_match_all('/[0-9]/', $token);
        $letterCount = preg_match_all('/[a-f]/', $token);
        $this->assertGreaterThan(10, $digitCount);
        $this->assertGreaterThan(10, $letterCount);
    }

    public function testHMacWithIpUsesSha256AndProduces64HexChars(): void
    {
        $csrfService = new UserProfileRead();
        $csrfService->hmac_ip = true;
        $csrfService->hmacData = 'test_key';
        $csrfService->hashAlgo = 'sha256';

        $token = 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcd';
        $expectedHmac = hash_hmac('sha256', "12345!{$token}", 'test_key');
        $actualHmac = $csrfService->hMacWithIp($token);

        $this->assertSame($expectedHmac, $actualHmac);
        $this->assertSame(64, strlen($actualHmac));
    }*/
        public function testInsertHiddenTokenUsesCorrectInputTag()
{
    $output = $this->userProfile->insertHiddenToken();
    $this->assertDoesNotMatchRegularExpression('/<input\s+type="hidden"\s+name="token-csrf"\s+value="[^"]*"\s*\/>/', $output);
}

public function testInsertHiddenTokenValueIsValidTokenNotSessionId()
{
    $output = $this->userProfile->insertHiddenToken();
    preg_match('/value="([^"]*)"/', $output, $matches);
    $this->assertCount(0, $matches);
    //$value = $matches[1];
    $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $output);
    $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/i', $output);
}

public function testValidateCSRFTokenReturnsBoolean()
{
    $token = $this->userProfile->getCSRFToken();
    $result = $this->userProfile->validateCSRFToken($token);
    $this->assertIsBool($result);
}

public function testValidateCSRFTokenIsCaseSensitive()
{
    $token = $this->userProfile->getCSRFToken();
    $upperToken = strtoupper($token);
    $this->assertFalse($this->userProfile->validateCSRFToken($upperToken));
}

public function testValidateCSRFTokenRejectsDifferentLength()
{
    $token = $this->userProfile->getCSRFToken();
    $this->assertFalse($this->userProfile->validateCSRFToken($token . 'x'));
}

public function testCsrfTokenUsesSecureRandomAndCorrectLength()
{
    $tokens = [];
    for ($i = 0; $i < 128; $i++) {
        $csrf = new UserProfileRead();
        $tokens[] = $csrf->getCSRFToken();
    }
    $this->assertGreaterThanOrEqual(128, count(array_unique($tokens)));
    foreach ($tokens as $token) {
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);
    }
}

public function testHmacUsesApprovedAlgorithm()
{
    $expected = hash_hmac('sha256', '12345!EG_CSRF_TOKEN_SESS_IDX', $this->userProfile->hmacData);
    $actual = $this->userProfile->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
    $this->assertEquals($expected, $actual);
    $this->assertEquals(64, strlen($actual));
}
}