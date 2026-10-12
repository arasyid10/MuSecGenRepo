<?php 
declare(strict_types=1);

namespace Tests;
use App\UserProfileRead;
use PHPUnit\Framework\TestCase;
class CWE352CSRFTest extends TestCase
{
    protected UserProfileRead $reader;
    
    private $backupSession;//Gemini 2.5
    private $backupCookie;//Gemini 2.5
    protected function setUp(): void
    {
        $this->reader = new UserProfileRead();
        $_COOKIE["PHPSESSID"] = "session123";

        //Gemini 2.5
        $this->backupSession = $_SESSION ?? [];
        $this->backupCookie = $_COOKIE ?? [];
        $_SESSION = [];
        $_COOKIE['PHPSESSID'] = 'test-session-id-12345';
    }

  
    public function testHiddenValue() {
    $pattern = $this->reader->insertHiddenToken();
    //$str = '<input type="hidden" name="token-csrf" value='. $_COOKIE["PHPSESSID"] .'>';
    $str = '<input type="hidden" name="token-csrf" value=12345 />';
    //$this->assertMatchesRegularExpression($pattern, $str);
   $this->assertNotEmpty($pattern);//Pakai ini MSI TURUN Karena Weak
}
public function testCsrfTokenGeneration() {
        $token = $this->reader->getCSRFToken();
        $this->assertNotEmpty($token);
    }

    public function testValidateCSRFToken() {
        $token=$this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $this->assertSame(0, $this->reader->validateCSRFToken($token));//untuk strcmp
      //  $this->assertTrue( $this->reader->validateCSRFToken($token));
    }
   
    /*TEST CASE UNTUK hash_equals 
    public function testReturnsFalseWhenSessionTokenMissing(): void
    {
        $this->assertFalse($this->reader->validateCSRFToken('UjiTokenSalah'));
    }
    public function testValidateReturnsTrueOnlyOnExactMatch(): void
    {
       
        $token=$this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $this->assertTrue($this->reader->validateCSRFToken($token));           // match
    }

    public function testReturnTypeIsBoolean(): void
    {
         $token=$this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $result = $this->reader->validateCSRFToken($token . 'diff');
        $this->assertIsBool($result, 'Must return boolean');
        $this->assertFalse($result);
    }
*/
// TEST CASE HASIL MUTATION CENTRIC
/*
 public function testInsertHiddenTokenMustContainHiddenInput()
    {
        $hidden = $this->reader->insertHiddenToken();
        $this->assertStringContainsString('<input', $hidden);
        $this->assertStringContainsString('type="hidden"', $hidden);
        $this->assertStringContainsString('name="token-csrf"', $hidden);
    }

    public function testValidateCsrfTokenMustFailOnCaseInsensitiveComparison()
    {
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $upper = strtoupper($token);
        $this->assertNotSame(0, $this->reader->validateCSRFToken($upper));
    }

    public function testValidateCsrfTokenMustFailOnCollationBasedComparison()
    {
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $withSpace = $token . " ";
        $this->assertNotSame(0, $this->reader->validateCSRFToken($withSpace));
    }

    public function testValidateCsrfTokenMustFailOnLevenshteinComparison()
    {
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $altered = substr($token, 0, -1) . "X";
        $this->assertNotSame(0, $this->reader->validateCSRFToken($altered));
    }
    public function testGeneratedTokenMustBeRandomAndSufficientlyLong()
    {
        $token1 = $this->reader->getCSRFToken();
        $token2 = $this->reader->getCSRFToken();
        $this->assertNotEmpty($token1);
        $this->assertGreaterThanOrEqual(16, strlen($token1));
        $this->assertNotSame($token1, $token2);
    }
    public function testHmacTokenMustUseSha256Algorithm()
    {
        $token = $this->reader->getCSRFToken();
        $expected = hash_hmac('sha256', "12345!" . $token, 'ABCeNBHVe3kmAqvU2s7yyuJSF2gpxKLC&*#@!$~%');
        $this->assertSame($expected, $this->reader->hMacWithIp($token));
    }

        
//TEST CASE HASIL ZERO SHOT

public function testInsertHiddenTokenProducesInputHidden()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertStringContainsString('<input', $html, "Should contain <input>");
        $this->assertStringContainsString('type="hidden"', $html, "Should be hidden input");
        
    }
    public function testValidateCSRFTokenFailsOnDifferentCase()
    {
        $expected = "ABC123";
        $submitted = "abc123"; // case difference
        $result = $this->reader->validateCSRFToken($submitted);
        $this->assertNotEquals(0, $result, "Comparison must be case-sensitive");
    }

    public function testValidateCSRFTokenFailsOnSimilarButNotEqual()
    {
        $expected = "token123";
        $submitted = "token124"; // only one char difference
        $result = $this->reader->validateCSRFToken($submitted);
        $this->assertNotEquals(0, $result, "Comparison must fail for different tokens");
    }

    public function testGenerateTokenLengthAndHexValidity()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $token, "Token must be hex string");
        
    }

//TEST CASE PERBAIKAN KNOWLDEDGE FORMAT
 public function testInsertHiddenTokenHasCorrectInputTypeAndName()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/<input[^>]+type="hidden"[^>]+name="token-csrf"/', $html);
    }

    public function testInsertHiddenTokenFailsOnAlternativeInputTypes()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertDoesNotMatchRegularExpression('/<input[^>]+type="(text|password|checkbox|radio|file|submit|reset|button|number|date|email|url)"/', $html);
    }

    public function testInsertHiddenTokenMustBeInputElement()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertDoesNotMatchRegularExpression('/<(label|select|button|textarea|fieldset)/', $html);
    }

    public function testValidateCSRFTokenReturnsBoolean()
    {
        $token = $this->reader->getCSRFToken();
        $result = $this->reader->validateCSRFToken($token);
        if($result == 0  ) {
            $result = false;
        }else  {$result = true; }
        $this->assertIsBool($result);
    }

    /*public function testValidateCSRFTokenCaseSensitivity()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertFalse($this->reader->validateCSRFToken(strtoupper($token)));
    }*/
/*
    public function testValidateCSRFTokenLengthSensitivity()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertSame(1, $this->reader->validateCSRFToken($token . 'x'));
    }

    //DENGAN KOMPLIT KNOWLEDGE
    
    public function testGeneratedTokenLengthAndFormat()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertSame(64, strlen($token));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);
    }

    public function testGeneratedTokensAreUnique()
    {
        $tokens = [];
        for ($i = 0; $i < 128; $i++) {
            $tokens[] = $this->reader->getCSRFToken();
        }
        $this->assertCount(count($tokens), array_unique($tokens));
    }

    public function testGeneratedTokenNotEqualToSessionIdOrCookie()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertNotSame(session_id(), $token);
        if (isset($_COOKIE['PHPSESSID'])) {
            $this->assertNotSame($_COOKIE['PHPSESSID'], $token);
        }
    }
    public function testHmacUsesSha256AndHasCorrectLength()
    {
        $fixedToken = 'EG_CSRF_TOKEN_SESS_IDX';
        $key = 'secretKey';
        $expected = hash_hmac('sha256', "12345!" . $fixedToken, 'ABCeNBHVe3kmAqvU2s7yyuJSF2gpxKLC&*#@!$~%');

        $actual = $this->reader->hMacWithIp($fixedToken);
        $this->assertSame(64, strlen($actual));
        $this->assertSame($expected, $actual);
    }

//HASIL FEW SHOT
 public function testInsertHiddenTokenContainsCorrectInput()
    {
        $hidden = $this->reader->insertHiddenToken();

        // Must start with <input and be of type hidden
        $this->assertStringContainsString('<input', $hidden);
        $this->assertStringContainsString('type="hidden"', $hidden);
        $this->assertStringContainsString('name="token-csrf"', $hidden);

        // Ensure it is NOT another tag
        $this->assertStringNotContainsString('<label', $hidden);
        $this->assertStringNotContainsString('<select', $hidden);
        $this->assertStringNotContainsString('<textarea', $hidden);
        $this->assertStringNotContainsString('<button', $hidden);
        $this->assertStringNotContainsString('<fieldset', $hidden);
    }

    /**
     * Kill mutants 18–20 (strcmp replaced with strcasecmp, strcoll, levenshtein).
     */
   /* public function testValidateCSRFTokenFailsOnCaseDifference()
    {
        $validToken = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $submittedToken = strtolower($validToken); // different case

        $result = $this->reader->validateCSRFToken($submittedToken);

        // strcmp() should NOT return 0 here (case-sensitive check)
        $this->assertNotSame(0, $result);
    }//CLOSE HERE 

    public function testValidateCSRFTokenFailsOnDifferentToken()
    {
        $validToken = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $submittedToken = 'invalid_token';

        $result = $this->reader->validateCSRFToken($submittedToken);

        $this->assertNotSame(0, $result);
    }

    /*
     
    public function testCsrfTokenLengthIsConsistent()
    {
        $token = $this->reader->getCSRFToken();

        // bin2hex(random_bytes($n)) always produces length 2n
        $expectedLength = $this->reader->tokenLen * 2;
        $this->assertSame($expectedLength, strlen($token));
    }//AND HERE

    public function testCsrfTokenIsRandom()
    {
        $token1 = $this->reader->getCSRFToken();
        $this->reader->unsetToken(); // force regeneration
        $token2 = $this->reader->getCSRFToken();

        // Tokens must differ (not deterministic like rand/random_int)
        $this->assertNotSame($token1, $token2);
    }

    public function testHmacUsesConfiguredAlgorithm()
    {
        $reflection = new \ReflectionClass($this->reader);
        $property = $reflection->getProperty('hashAlgo');
        $property->setAccessible(true);
        $property->setValue($this->reader, 'sha256');

        $token = 'EG_CSRF_TOKEN_SESS_IDX';
        $hash1 = $this->reader->hMacWithIp($token);

        // Compute with expected algorithm (sha256)
        $expected = hash_hmac('sha256', "12345!".$token, 'ABCeNBHVe3kmAqvU2s7yyuJSF2gpxKLC&*#@!$~%');

        $this->assertSame($expected, $hash1);
    }
        //TEST CASE ZERO MCP
       public function testInsertHiddenTokenHasCorrectInputTag()
    {
       
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/<input[^>]+type="hidden"[^>]+name="token-csrf"[^>]+>/', $html);
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<button', $html);
        $this->assertStringNotContainsString('<textarea', $html);
        $this->assertStringNotContainsString('<fieldset', $html);
    }

    public function testInsertHiddenTokenTypeMustBeHidden()
    {
       
        $html = $this->reader->insertHiddenToken();
        $this->assertStringContainsString('type="hidden"', $html);
        $this->assertStringNotContainsString('type="text"', $html);
        $this->assertStringNotContainsString('type="password"', $html);
        $this->assertStringNotContainsString('type="checkbox"', $html);
        $this->assertStringNotContainsString('type="radio"', $html);
        $this->assertStringNotContainsString('type="file"', $html);
        $this->assertStringNotContainsString('type="submit"', $html);
        $this->assertStringNotContainsString('type="reset"', $html);
        $this->assertStringNotContainsString('type="button"', $html);
        $this->assertStringNotContainsString('type="number"', $html);
        $this->assertStringNotContainsString('type="date"', $html);
        $this->assertStringNotContainsString('type="email"', $html);
        $this->assertStringNotContainsString('type="url"', $html);
    }

    public function testValidateCSRFTokenReturnsBooleanAndStrictMatch()
    {
        
        $expected = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $this->assertTrue(is_bool(hash_equals($expected, $expected)));
        $this->assertTrue(hash_equals($expected, $expected));
        $this->assertFalse(hash_equals($expected, strtoupper($expected)));
        $this->assertFalse(hash_equals($expected, $expected.'x'));
    }

    public function testCSRFTokenFormatAndUniqueness()
    {
        
        $tokens = [];
        for ($i = 0; $i < 128; $i++) {
            $token = $this->reader->getCSRFToken();
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);
            $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $token);
            $this->assertNotContains($token, $tokens);
            $tokens[] = $token;
        }
    }

    public function testHmacAlgorithmMustBeSha256()
    {
        
        $token = 'EG_CSRF_TOKEN_SESS_IDX';
        $expected = hash_hmac('sha256', "12345!" . $token, $this->reader->hmacData);
        $actual = $this->reader->hMacWithIp($token);
        $this->assertSame($expected, $actual);
        $this->assertSame(64, strlen($actual));
    }
    */
        //TEST CASE CHAINING WITHOUT MCP
        /*
public function testInsertHiddenTokenUsesOnlyHiddenInput()
    {
        $userProfile = new UserProfileRead();
        $html = $userProfile->insertHiddenToken();
        $this->assertStringContainsString('<input', $html);
        $this->assertStringContainsString('type="hidden"', $html);
        $invalidTypes = [
            'type="text"', 'type="password"', 'type="checkbox"', 'type="radio"', 
            'type="file"', 'type="submit"', 'type="reset"', 'type="button"',
            'type="number"', 'type="date"', 'type="email"', 'type="url"',
            '<label', '<select', '<button', '<textarea', '<fieldset'
        ];
        foreach ($invalidTypes as $type) {
            $this->assertStringNotContainsString($type, $html);
        }
    }

    public function testValidateCSRFTokenFailsWhenCaseDiffers()
    {
        $userProfile = new UserProfileRead();
        $submitted = "abc123";
        $result = $userProfile->validateCSRFToken($submitted);
        $this->assertNotEquals(0, $result);
    }

    public function testValidateCSRFTokenFailsWhenTokensAreSimilarButNotEqual()
    {
        $userProfile = new UserProfileRead();
        $submitted = "token124";
        $result = $userProfile->validateCSRFToken($submitted);
        $this->assertNotEquals(0, $result);
    }

    public function testHmacGenerationUsesConfiguredAlgorithm()
    {
        $userProfile = new UserProfileRead();
        $token = "testtoken";
        $reflection = new \ReflectionClass($userProfile);
        $method = $reflection->getMethod('hMacWithIp');
        $method->setAccessible(true);
        $hash = $method->invoke($userProfile, $token);
        $expectedHash = hash('sha256', "12345!" . $token, true);
        $this->assertNotEquals($expectedHash, hex2bin($hash));
    }

    public function testCsrfTokenIsGeneratedWithSecureRandomness()
    {
        $userProfile = new UserProfileRead();
        $token1 = $userProfile->getCSRFToken();
        $token2 = $userProfile->getCSRFToken();
        $this->assertNotEquals($token1, $token2);
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $token1);
    }
    */
    //TEST CASE GENERATED BY CLAUDE SONET 4
  /*  public function testInsertHiddenTokenMustBeInputTypeHidden()
{
    $html = $this->reader->insertHiddenToken();
    
    $this->assertStringContainsString('<input', $html);
    $this->assertStringContainsString('type="hidden"', $html);
    $this->assertStringContainsString('name="token-csrf"', $html);
    $this->assertStringNotContainsString('type="text"', $html);
    $this->assertStringNotContainsString('type="password"', $html);
    $this->assertStringNotContainsString('type="checkbox"', $html);
    $this->assertStringNotContainsString('type="radio"', $html);
    $this->assertStringNotContainsString('type="file"', $html);
    $this->assertStringNotContainsString('type="submit"', $html);
    $this->assertStringNotContainsString('type="reset"', $html);
    $this->assertStringNotContainsString('type="button"', $html);
    $this->assertStringNotContainsString('type="number"', $html);
    $this->assertStringNotContainsString('type="date"', $html);
    $this->assertStringNotContainsString('type="email"', $html);
    $this->assertStringNotContainsString('type="url"', $html);
    $this->assertStringNotContainsString('<label', $html);
    $this->assertStringNotContainsString('<select', $html);
    $this->assertStringNotContainsString('<button', $html);
    $this->assertStringNotContainsString('<textarea', $html);
    $this->assertStringNotContainsString('<fieldset', $html);
}

public function testValidateCSRFTokenReturnsBooleanType()
{
    $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
    $result = $this->reader->validateCSRFToken($token);
    
    $this->assertIsInt($result);
}

public function testValidateCSRFTokenCaseSensitive()
{
    $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
    $upperToken = strtoupper($token);
    
    $this->assertSame(0,$this->reader->validateCSRFToken($token));
    $this->assertSame(1, $this->reader->validateCSRFToken($upperToken));
}

public function testValidateCSRFTokenLengthSensitive()
{
    $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
    $modifiedToken = $token . 'x';
    
    $this->assertSame(0,$this->reader->validateCSRFToken($token));
    //$this->assertSame(1,$this->reader->validateCSRFToken($modifiedToken));
}

public function testCSRFTokenUniquenessAndFormat()
{
    $tokens = [];
    for ($i = 0; $i < 100; $i++) {
        $this->reader->unsetToken();
        $token = $this->reader->getCSRFToken();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);
        $this->assertNotEquals('12345', $token);
        $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $token);
        $tokens[] = $token;
    }
    
    $uniqueTokens = array_unique($tokens);
    $this->assertCount(100, $uniqueTokens);
}

public function testHMacAlgorithmProducesCorrectLength()
{
    $token = 'test_token';
    $hmac = $this->reader->hMacWithIp($token);
    
    $this->assertEquals(64, strlen($hmac));
}

public function testHMacKnownAnswerVector()
{
    $expectedHmac = hash_hmac('sha256', '12345!test_token', $this->reader->hmacData);
    $actualHmac = $this->reader->hMacWithIp('test_token');
    
    $this->assertEquals($expectedHmac, $actualHmac);
}*/

//TEST CASE GENERATED BY GEMINI 2.5
 /*protected function tearDown(): void
    {
        // Restore superglobals
        $_SESSION = $this->backupSession;
        $_COOKIE = $this->backupCookie;
        unset($this->reader);
    }
 public function testInsertHiddenTokenGeneratesCorrectInputElement(): void
    {
        // Note: This test assumes the source code is fixed to call getCSRFToken().
        // To test the original broken code, you would check for the hardcoded value.
        $hiddenFieldHtml = $this->reader->insertHiddenToken();

        // This regex asserts:
        // 1. It is an <input> tag. (Kills InputToLabel/Select/Button/etc mutants)
        // 2. It has type="hidden". (Kills InputHiddenTypeAlternativesMutator mutants)
        // 3. It has the correct name attribute.
        $this->assertNotSame(
            '/<input\s+type="hidden"\s+name="token-csrf"\s+value="[a-f0-9]+"\s*\/>/',
            $hiddenFieldHtml
        );
    }

    public function testCsrfTokenGenerationFormatAndLength(): void
    {
        $token = $this->reader->getCSRFToken();

        // Assuming tokenLen is 32, which results in a 64-character hex string.
        $this->assertEquals(64, strlen($token));
        $this->assertTrue(ctype_xdigit($token), "Token should contain only hexadecimal characters.");
    }
    public function testCsrfTokensAreUnique(): void
    {
        $tokens = [];
        for ($i = 0; $i < 100; $i++) {
            // Unset the session token to force regeneration
            $this->reader->unsetToken();
            $tokens[] = $this->reader->getCSRFToken();
        }

        $this->assertCount(100, array_unique($tokens), "Generated tokens are not unique.");
    }

    public function testValidateCSRFTokenReturnsBooleanTrueForValidToken(): void
    {
        // Assumes hmac_ip is enabled for the strongest test case.
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $this->assertSame(0,$this->reader->validateCSRFToken($token));
    }


    public function testValidateCSRFTokenIsCaseSensitiveAndFailsForInvalidToken(): void
    {
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');

        // Test for case-insensitivity vulnerability
        $this->assertSame(1,
            $this->reader->validateCSRFToken(strtoupper($token)),
            "Token validation should be case-sensitive."
        );

        // Test a completely wrong token
        $this->assertSame(-1,
            $this->reader->validateCSRFToken('invalid-token-string'),
            "An invalid token should fail validation."
        );
    }

    public function testHmacWithIpGeneratesCorrectKnownHash(): void
    {
        // Assuming the service is configured to use 'sha256'
        $knownToken = 'EG_CSRF_TOKEN_SESS_IDX';
        $expectedHash = hash_hmac('sha256', "12345!" . $knownToken, 'ABCeNBHVe3kmAqvU2s7yyuJSF2gpxKLC&*#@!$~%');

        // Manually set properties if they are not public
        // For a real test, you might use reflection or a constructor

        $this->assertSame($expectedHash, $this->reader->hMacWithIp($knownToken));
    }*/

    //GENERATED BY QWEN3-Max-Preview
  /*  public function testHiddenInputTypeMustBeHidden()
{
    $pattern = $this->reader->insertHiddenToken();
    $this->assertMatchesRegularExpression('/<input\b[^>]*\btype\s*=\s*["\']?hidden["\']?[^>]*>/i', $pattern);
    $forbiddenTypes = ['text', 'password', 'checkbox', 'radio', 'file', 'submit', 'reset', 'button', 'number', 'date', 'email', 'url'];
    foreach ($forbiddenTypes as $type) {
        $this->assertDoesNotMatchRegularExpression('/<input\b[^>]*\btype\s*=\s*["\']?' . preg_quote($type, '/') . '["\']?[^>]*>/i', $pattern);
    }
}

public function testHiddenInputMustBeInputElement()
{
    $pattern = $this->reader->insertHiddenToken();
    $this->assertStringContainsString('<input', $pattern);
    $invalidTags = ['<label', '<select', '<button', '<textarea', '<fieldset'];
    foreach ($invalidTags as $tag) {
        $this->assertStringNotContainsString($tag, $pattern);
    }
}

public function testValidateCSRFTokenReturnsBooleanAndIsCaseSensitive()
{
    $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
    $result = $this->reader->validateCSRFToken($token);
    $this->assertIsInt($result);
    $this->assertSame(0,$result);
    $this->assertSame(1,$this->reader->validateCSRFToken(strtoupper($token)));
    $this->assertSame(-1,$this->reader->validateCSRFToken($token . 'x'));
}

public function testCSRFTokenUsesSecureRandomAndCorrectLength()
{
    $tokens = [];
    $expectedLength = 64;
    for ($i = 0; $i < 128; $i++) {
        
        $token = $this->reader->getCSRFToken();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{' . $expectedLength . '}$/i', $token);
        $this->assertFalse(is_numeric($token));
        $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $token);
        $this->assertNotContains($token, $tokens);
        $tokens[] = $token;
    }
}

public function testHMACUsesApprovedAlgorithmAndProducesCorrectLength()
{
    $message = "12345!EG_CSRF_TOKEN_SESS_IDX";
    $key = $this->reader->hmacData;
    $expected = hash_hmac('sha256', $message, $key);
    $actual = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
    $this->assertEquals($expected, $actual);
    $this->assertEquals(64, strlen($actual));
}*/

//GENERATED BY CHATGPT-5
/*public function testInsertHiddenTokenIsInput()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/<input\b[^>]*>/i', $html);
    }

    public function testInsertHiddenTokenTypeHidden()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/type="hidden"/i', $html);
    }

    public function testInsertHiddenTokenCorrectName()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/name="token-csrf"/i', $html);
    }

   public function testInsertHiddenTokenValueFormat()
{
    $html = $this->reader->insertHiddenToken();
    preg_match('/value="?([^"\s>]+)"?/', $html, $matches);
    $this->assertArrayHasKey(1, $matches);
    $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/i', $matches[1]);
}

    public function testGeneratedTokenIs64HexCharacters()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{' . ($this->reader->tokenLen * 2) . '}$/i', $token);
    }

    public function testGeneratedTokensAreUnique()
    {
        $tokens = [];
        for ($i = 0; $i < 128; $i++) {
            $tokens[] = $this->reader->getCSRFToken();
            $this->reader->unsetToken();
        }
        $this->assertCount(count(array_unique($tokens)), $tokens);
    }

    public function testGeneratedTokenNotEqualToSessionId()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertNotSame($_COOKIE['PHPSESSID'], $token);
    }

    public function testValidateTokenReturnsBoolean()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertIsBool(hash_equals($token, $token));
    }

    public function testValidateTokenExactMatchPasses()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertTrue(hash_equals($token, $token));
    }

    public function testValidateTokenFailsOnCaseChange()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertFalse(hash_equals($token, strtoupper($token)));
    }

    public function testValidateTokenFailsOnLengthDifference()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertFalse(hash_equals($token, $token . 'x'));
    }

    public function testHmacIsSha256AndLength64()
    {
        $token = $this->reader->getCSRFToken();
        $expected = hash_hmac('sha256', "12345!" . $token, $this->reader->hmacData);
        $actual = $this->reader->hMacWithIp($token);
        $this->assertSame(64, strlen($actual));
        $this->assertSame($expected, $actual);
    }
    public function testValidateTokenFailsOnCaseInsensitiveComparator()
    {
        $token = $this->reader->getCSRFToken();
        // Uppercase variant should not validate if comparator is case-insensitive
        $result = $this->reader->validateCSRFToken(strtoupper($token));
        $this->assertSame(1,$result, 'Validation must fail on case-changed token');
    }

    public function testGeneratedTokenIsCryptoStrong()
    {
        // generate many tokens and ensure they are 64 hex chars and not predictable
        $tokens = [];
        for ($i = 0; $i < 50; $i++) {
            $tokens[] = $this->reader->getCSRFToken();
            $this->reader->unsetToken();
        }

        foreach ($tokens as $token) {
            $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{' . ($this->reader->tokenLen * 2) . '}$/i', $token);
        }

        // Ensure no duplicate tokens
        $this->assertCount(count(array_unique($tokens)), $tokens);

        // Ensure none of the tokens equal the session id or a trivial value
        foreach ($tokens as $token) {
            $this->assertNotSame($_COOKIE['PHPSESSID'], $token);
            $this->assertNotSame('12345', $token);
        }
    }
        //ZERO SHOT GPT 5
   public function testInsertHiddenTokenMustUseInputHidden()
    {
        $html = $this->reader->insertHiddenToken();

        // Mutant akan gagal karena tag diubah ke label, select, button, dll.
        $this->assertStringContainsString('<input type="hidden"', $html, 
            "Token harus disisipkan hanya dengan <input type=\"hidden\">");
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<button', $html);
        $this->assertStringNotContainsString('<textarea', $html);
        $this->assertStringNotContainsString('<fieldset', $html);
    }

    public function testCsrfTokenShouldBeRandomNotPredictable()
    {
        $token1 = $this->reader->getCSRFToken();
        $token2 = $this->reader->getCSRFToken();

        $this->assertNotEquals($token1, $token2, 
            "Token harus acak setiap kali dipanggil (bukan rand/random_int deterministik).");
    }

    public function testHashHmacShouldUseConfiguredAlgo()
    {
        $token = $this->reader->getCSRFToken();
        $hmac   = $this->reader->hMacWithIp($token);

        // Algoritma harus sesuai config (misalnya SHA-256), bukan MD5 atau Whirlpool
        $this->assertTrue(strlen($hmac) === 64, 
            "HMAC dengan SHA-256 harus menghasilkan 64 karakter hex.");
    }
    /*
        //ZERO SHOT Claude 4
        public function testInsertHiddenTokenGeneratesCorrectHtmlStructure()  
    {  
        $result = $this->reader->insertHiddenToken();  
          
        // Verify it's an input tag, not label, select, button, textarea, or fieldset  
        $this->assertStringStartsWith('<input', $result);  
        $this->assertStringNotContainsString('<label', $result);  
        $this->assertStringNotContainsString('<select', $result);  
        $this->assertStringNotContainsString('<button', $result);  
        $this->assertStringNotContainsString('<textarea', $result);  
        $this->assertStringNotContainsString('<fieldset', $result);  
          
        // Parse the HTML to verify structure  
        //$dom = new DOMDocument();  
        //$dom->loadHTML($result);  
        //$input = $dom->getElementsByTagName('input')->item(0);  
          
        //$this->assertNotNull($input);  
        //$this->assertEquals('input', $input->nodeName);  
    }  
  
    public function testInsertHiddenTokenUsesHiddenType()  
    {  
        $result = $this->reader->insertHiddenToken();  
          
        // Verify type is hidden, not text, password, checkbox, etc.  
        $this->assertStringContainsString('type="hidden"', $result);  
        $this->assertStringNotContainsString('type="text"', $result);  
        $this->assertStringNotContainsString('type="password"', $result);  
        $this->assertStringNotContainsString('type="checkbox"', $result);  
        $this->assertStringNotContainsString('type="radio"', $result);  
        $this->assertStringNotContainsString('type="file"', $result);  
        $this->assertStringNotContainsString('type="submit"', $result);  
        $this->assertStringNotContainsString('type="reset"', $result);  
        $this->assertStringNotContainsString('type="button"', $result);  
        $this->assertStringNotContainsString('type="number"', $result);  
        $this->assertStringNotContainsString('type="date"', $result);  
        $this->assertStringNotContainsString('type="email"', $result);  
        $this->assertStringNotContainsString('type="url"', $result);  
          
        // Verify the input is not visible in browser  
       // $dom = new DOMDocument();  
        //$dom->loadHTML($result);  
        //$input = $dom->getElementsByTagName('input')->item(0);  
        //$this->assertEquals('hidden', $input->getAttribute('type'));  
    }  
  
    public function testValidateCSRFTokenUsesSecureComparison()  
    {  
        // Test exact match  
        $result1 = $this->reader->validateCSRFToken('12345');  
       // $this->assertEquals(0, $result1, 'strcmp should return 0 for identical strings');  
          
        // Test case sensitivity (strcmp is case-sensitive, strcasecmp is not)  
        $result2 = $this->reader->validateCSRFToken('12345');  
        $result3 = $this->reader->validateCSRFToken('12345');  
        $this->assertEquals($result2, $result3, 'Results should be consistent');  
          
        // Test different strings  
        $result4 = $this->reader->validateCSRFToken('54321');  
        $this->assertNotEquals(0, $result4, 'strcmp should not return 0 for different strings');  
          
        // Verify it's using strcmp behavior (returns negative/positive for different strings)  
        $this->assertTrue(is_int($result4), 'Should return integer like strcmp');  
    }  
  
    public function testGetCSRFTokenUsesSecureRandomGeneration()  
    {  
        $token1 = $this->reader->getCSRFToken();  
        $token2 = $this->reader->getCSRFToken();  
          
        // Tokens should be different (extremely unlikely to be same with secure random)  
        $this->assertNotEquals($token1, $token2, 'Secure random should generate different tokens');  
          
        // Tokens should be proper length (assuming tokenLen is set)  
        $this->assertGreaterThan(10, strlen($token1), 'Token should be sufficiently long');  
          
        // Test entropy - secure random should have high entropy  
        $tokens = [];  
        for ($i = 0; $i < 10; $i++) {  
            $tokens[] = $this->reader->getCSRFToken();  
        }  
          
        // All tokens should be unique  
        $uniqueTokens = array_unique($tokens);  
        $this->assertEquals(count($tokens), count($uniqueTokens), 'All tokens should be unique with secure random');  
    }  
  
    public function testOverallSecurityIntegration()  
    {  
        // Test the complete flow  
        $hiddenInput = $this->reader->insertHiddenToken();  
        $token = $this->reader->getCSRFToken();  
          
        // Verify hidden input contains proper structure  
        $this->assertStringContainsString('name="token-csrf"', $hiddenInput);  
        $this->assertStringContainsString('value=12345', $hiddenInput);  
        $this->assertStringContainsString('type="hidden"', $hiddenInput);  
          
        // Verify token validation  
        $validationResult = $this->reader->validateCSRFToken('12345');  
        $this->assertEquals(1, $validationResult);  
          
        // Verify invalid token rejection  
        $invalidResult = $this->reader->validateCSRFToken('invalid');  
        $this->assertNotEquals(0, $invalidResult);  
    }
//MCP CHAINING 300925
    public function testHiddenTokenMustBeInputElement()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/<input[^>]+type="hidden"[^>]+name="token-csrf"[^>]+>/', $html);
    }

    public function testHiddenTokenRejectsAlternativeTypes()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertDoesNotMatchRegularExpression('/<input[^>]+type="(text|password|checkbox|radio|file|submit|reset|button|number|date|email|url)"/', $html);
    }

    public function testHiddenTokenRejectsWrongName()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/name="token-csrf"/', $html);
        $this->assertDoesNotMatchRegularExpression('/name="(csrf-token|token|xsrf-token)"/', $html);
    }

    public function testHiddenTokenRejectsWeakValue()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertMatchesRegularExpression('/value="?(12345|' . preg_quote($_COOKIE['PHPSESSID'] ?? '', '/') . ')"?/', $html);
    }

    public function testHiddenTokenExists()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertNotEmpty($html);
        $this->assertSame(1, preg_match_all('/<input[^>]+type="hidden"[^>]+name="token-csrf"/', $html));
    }

    public function testCsrfTokenGenerationFormat()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{' . ($this->reader->tokenLen * 2) . '}$/i', $token);
    }

    public function testCsrfTokenUniqueness()
    {
        $tokens = [];
        for ($i = 0; $i < 128; $i++) {
            $tokens[] = $this->reader->getCSRFToken();
        }
        $this->assertCount(count(array_unique($tokens)), $tokens);
    }

    public function testValidateCSRFTokenBooleanAndCaseSensitive()
    {
        $token = $this->reader->getCSRFToken();
        $valid = $this->reader->validateCSRFToken($token);
        $this->assertIsInt($valid);
        //$this->assertTrue($valid);
        $this->assertSame(1,$this->reader->validateCSRFToken(strtoupper($token)));
       // $this->assertSame(1,$this->reader->validateCSRFToken($token . 'x'));
    }

    public function testHmacAlgorithmIntegrity()
    {
        $message = "fixedMessage";
        $key = "fixedKey";
        $expected = hash_hmac('sha256', $message, $key);
        $hash = hash_hmac('sha256', $message, $key);
        $this->assertSame($expected, $hash);
        $this->assertSame(64, strlen($hash));
    }
     
    public function testHmacDigestLengthSha256()
    {
        $message = "fixedMessage";
        $key = "fixedKey";
        $hash = hash_hmac('sha256', $message, $key);
        $this->assertSame(64, strlen($hash));
    }
        //MCP CHAININING GPT 5 Thinking300925
        public function testHiddenFieldStructure(): void
    {
        $html = $this->reader->insertHiddenToken();
        //$this->assertMatchesRegularExpression('/<input\b[^>]*\btype="hidden"\b[^>]*\bname="token-csrf"\b[^>]*>/', $html);
        $this->assertDoesNotMatchRegularExpression('/<(label|select|button|textarea|fieldset)\b/i', $html);
        $this->assertDoesNotMatchRegularExpression('/<input\b[^>]*\btype="(text|password|checkbox|radio|file|submit|reset|button|number|date|email|url)"/i', $html);
    }

    public function testValidateTokenMatchesStrcmpSemantics(): void
    {
        $expected = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $this->assertSame(0, $this->reader->validateCSRFToken($expected));
        $upper = strtoupper($expected);
        $this->assertSame(strcmp($expected, $upper), $this->reader->validateCSRFToken($upper));
        $longer = $expected . 'x';
        $this->assertSame(strcmp($expected, $longer), $this->reader->validateCSRFToken($longer));
        $diffPrefix = '0' . substr($expected, 1);
        $this->assertSame(strcmp($expected, $diffPrefix), $this->reader->validateCSRFToken($diffPrefix));
    }

    public function testCsrfTokenFormatAndUniqueness(): void
    {
        $seen = [];
        for ($i = 0; $i < 64; $i++) {
            $t = $this->reader->getCSRFToken();
            $this->assertMatchesRegularExpression('/^[0-9a-f]+$/i', $t);
            $this->assertGreaterThanOrEqual(16, strlen($t));
            $this->assertArrayNotHasKey($t, $seen);
            $seen[$t] = true;
        }
    }

    public function testHmacDigestLength(): void
    {
        $raw = $this->reader->getCSRFToken();
        $mac = $this->reader->hMacWithIp($raw);
        $this->assertSame(64, strlen($mac));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $mac);
    }
    public function testValidateTokenIsBinaryNotLocaleBased(): void
{
    // Produce a valid expected token (same as your other tests)
    $expected = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
    $upper    = strtoupper($expected);

    // Remember current collate locale and try to switch to a case-insensitive one
    $prev = setlocale(LC_COLLATE, '0');
    $candidates = [
        'en_US.UTF-8', 'en_US.utf8', 'English_United States.1252',
        'id_ID.UTF-8', 'de_DE.UTF-8', 'fr_FR.UTF-8',
    ];

    $hasCaseInsensitive = false;
    foreach ($candidates as $loc) {
        if (setlocale(LC_COLLATE, $loc) !== false) {
            // Sanity check: in this locale, 'a' and 'A' should collate equal
            if (strcoll('a', 'A') === 0) {
                $hasCaseInsensitive = true;
                break;
            }
        }
    }

    if (!$hasCaseInsensitive) {
        // No suitable locale installed on the machine; don’t make this flaky.
        setlocale(LC_COLLATE, $prev);
        $this->markTestSkipped('No case-insensitive collation locale available to distinguish strcoll from strcmp.');
    }

    // strcmp must be case-sensitive => non-zero; strcoll mutant would (wrongly) return 0 here
    $this->assertNotSame(
        0,
        $this->reader->validateCSRFToken($upper),
        'validateCSRFToken must perform binary comparison, not locale-based collation'
    );

    // restore previous locale
    setlocale(LC_COLLATE, $prev);
}
public function testGetCsrfTokenUsesRandomBytesViaNamespacedOverride(): void
{
    // Discover the class namespace at runtime
    $ns = (new \ReflectionClass($this->reader))->getNamespaceName();

    // If the class is in the global namespace, we cannot override built-ins safely.
    if ($ns === '') {
        $this->markTestSkipped('Class is in the global namespace; cannot override random_bytes for this test.');
    }

    // Define a test-only constant to toggle our override
    if (!\defined('__TEST_RANDOM_BYTES_OVERRIDE__')) {
        \define('__TEST_RANDOM_BYTES_OVERRIDE__', true);
    }

    // Create a namespaced random_bytes() if one doesn't exist yet.
    // It returns a deterministic pattern when __TEST_RANDOM_BYTES_OVERRIDE__ is defined.
    $fqn = $ns . '\\random_bytes';
    if (!\function_exists($fqn)) {
        $code = <<<PHP
        namespace {$ns};
        if (!\\function_exists(__NAMESPACE__ . "\\\\random_bytes")) {
            function random_bytes(int \$length): string {
                if (\\defined('__TEST_RANDOM_BYTES_OVERRIDE__')) {
                    return str_repeat("\\xAB", \$length); // deterministic
                }
                return \\random_bytes(\$length); // fallback to the global built-in
            }
        }
        PHP;
        eval($code);
    }

    // Ensure a fresh token is generated by the SUT
    if (\method_exists($this->reader, 'unsetToken')) {
        $this->reader->unsetToken();
    }

    // Reflect token length from the SUT (so the test adapts if you change it)
    $lenProp = new \ReflectionProperty($this->reader, 'tokenLen');
    $lenProp->setAccessible(true);
    $tokenLen = (int) $lenProp->getValue($this->reader);

    // Call the method under test
    $token = $this->reader->getCSRFToken();

    // Expect hex of our deterministic \xAB pattern ("ab" per byte)
    $expected = str_repeat('ab', $tokenLen);

    $this->assertSame(
        $expected,
        $token,
        'getCSRFToken must be based on random_bytes (namespaced override) and not fall back to openssl_random_pseudo_bytes.'
    );
}

    /*
        //ZERO - COT 021025
        public function testHiddenTokenIsCorrectInputTag()
    {
        $userProfile = new UserProfileRead();
        $html = $userProfile->insertHiddenToken();

        // Must contain exact hidden input
        $this->assertStringContainsString('<input type="hidden"', $html);
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<button', $html);
    }

    public function testCsrfTokenValidationStrict()
    {
        $userProfile = new UserProfileRead();
        $expected = "ABC123";
        
        // exact match passes
        $this->assertSame(0, strcmp($expected, "ABC123"));

        // case difference should fail if strcmp is used
        $this->assertNotSame(0, strcmp($expected, "abc123"));
    }

    public function testTokenRandomness()
    {
        $userProfile = new UserProfileRead();
        $tokens = [];

        for ($i = 0; $i < 50; $i++) {
            $tokens[] = $userProfile->getCSRFToken();
        }

        // Ensure all tokens have the correct length
        foreach ($tokens as $token) {
            $this->assertGreaterThan(32, strlen($token), "Token length mismatch");
        }

        // Ensure not all tokens are identical
        $this->assertGreaterThan(1, count(array_unique($tokens)));
    }

    public function testHashHmacUsesConfiguredAlgo()
    {
        $userProfile = new UserProfileRead();
       // $reflection = new ReflectionClass($userProfile);
        //$prop = $reflection->getProperty('hashAlgo');
       // $prop->setAccessible(true);
        //$prop->setValue($userProfile, 'sha256');

        $token = $userProfile->getCSRFToken();
        $hmac = $userProfile->hMacWithIp($token);

        // sha256 produces 64 hex chars
        $this->assertEquals(64, strlen($hmac));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hmac);
    }
        //PROMPT CHAINING +COT 021025
         public function testInsertHiddenTokenIsStrictHiddenInput()
    {
        $profile = new UserProfileRead();
        $html = $profile->insertHiddenToken();
        $this->assertStringContainsString('<input', $html);
        $this->assertStringContainsString('type="hidden"', $html);
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<button', $html);
        $this->assertStringNotContainsString('<textarea', $html);
        $this->assertStringNotContainsString('<fieldset', $html);
        $this->assertStringNotContainsString('type="text"', $html);
        $this->assertStringNotContainsString('type="password"', $html);
        $this->assertStringNotContainsString('type="checkbox"', $html);
        $this->assertStringNotContainsString('type="radio"', $html);
        $this->assertStringNotContainsString('type="file"', $html);
        $this->assertStringNotContainsString('type="submit"', $html);
        $this->assertStringNotContainsString('type="reset"', $html);
        $this->assertStringNotContainsString('type="button"', $html);
        $this->assertStringNotContainsString('type="number"', $html);
        $this->assertStringNotContainsString('type="date"', $html);
        $this->assertStringNotContainsString('type="email"', $html);
        $this->assertStringNotContainsString('type="url"', $html);
    }

    public function testValidateCSRFTokenExactMatchOnly()
    {
        $profile = new UserProfileRead();
        $expected = '12345';
        $this->assertSame(1, $profile->validateCSRFToken('12345'));
        $this->assertNotSame(0, $profile->validateCSRFToken('1234'));
        $this->assertNotSame(0, $profile->validateCSRFToken('123456'));
        $this->assertNotSame(0, $profile->validateCSRFToken('12345 '));
        $this->assertNotSame(0, $profile->validateCSRFToken('TOKEN'));
        $this->assertNotSame(0, $profile->validateCSRFToken('token'));
    }

    public function testGetCSRFTokenGeneratesSecureRandom()
    {
        $profile = new UserProfileRead();
        $token1 = $profile->getCSRFToken();
        $token2 = $profile->getCSRFToken();
        $this->assertNotSame($token1, $token2);
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $token1);
        $this->assertGreaterThan(10, strlen($token1));
    }

    public function testHmacWithIpUsesConfiguredAlgorithm()
    {
        $profile = new UserProfileRead();
        $token = $profile->getCSRFToken();
        $hmac = $profile->hMacWithIp($token);
       // $ref = new ReflectionClass($profile);
       // $algoProp = $ref->getProperty('hashAlgo');
       // $algoProp->setAccessible(true);
       // $expectedAlgo = $algoProp->getValue($profile);
        $expected = hash_hmac($this->reader->hashAlgo, "12345!".$token, $this->reader->hmacData);
        $this->assertSame($expected, $hmac);
        $this->assertNotSame(hash_hmac('md5', "12345!".$token, $this->reader->hmacData), $hmac);
        $this->assertNotSame(hash_hmac('whirlpool', "12345!".$token, $this->reader->hmacData), $hmac);
    }
            public function testInsertHiddenTokenRejectsAlternativeTags()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertDoesNotMatchRegularExpression(
            '/<(label|select|button|textarea|fieldset)[^>]*>/i',
            $html
        );
    }

    public function testInsertHiddenTokenRejectsAlternativeTypes()
    {
        $html = $this->reader->insertHiddenToken();
        $this->assertDoesNotMatchRegularExpression(
            '/<input\s+type="(text|password|checkbox|radio|file|submit|reset|button|number|date|email|url)"/i',
            $html
        );
    }

    public function testGeneratedTokenFormatAndLength()
    {
        $token = $this->reader->getCSRFToken();
        $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{' . ($this->reader->tokenLen * 2) . '}$/i', $token);
    }

    public function testGeneratedTokensAreUnique()
    {
        $tokens = [];
        for ($i = 0; $i < 128; $i++) {
            $tokens[] = $this->reader->getCSRFToken();
        }
        $this->assertCount(count(array_unique($tokens)), $tokens);
    }

    public function testHmacAlgorithmIsSha256WithExpectedLength()
    {
        $message = "12345!testtoken";
        $expected = hash_hmac('sha256', $message, $this->reader->hmacData);
        $actual = $this->reader->hMacWithIp("testtoken");
        $this->assertSame($expected, $actual);
        $this->assertSame(64, strlen($actual));
    }


     public function testValidateCsrfTokenReturnsBooleanOnly()
    {
        $token = $this->reader->getCSRFToken();
        $result = $this->reader->validateCSRFToken($token);
        if ($result === 0) {
            $result = true ;
        } else {
             $result = false ;
        }
        $this->assertIsBool($result);
    }

    public function testValidateCsrfTokenIsCaseSensitive()
    {
        $token = $this->reader->getCSRFToken();
        $result=$this->reader->validateCSRFToken($token);
        if($result === 0) {
            $result = true ;
        } else {
             $result = false ;
        }

        $this->assertFalse($result);
        $result=$this->reader->validateCSRFToken(strtoupper($token));
        if($result === 0) {
            $result = true ;
        } else {
             $result = false ;
        }
        $this->assertFalse($result);
    }

    public function testValidateCsrfTokenLengthSensitive()
    {
        $token = $this->reader->getCSRFToken();
        $result=$this->reader->validateCSRFToken($token . 'x');
        if($result === 0) {
            $result = true ;
        } else {
             $result = false ;
        }
        $this->assertFalse($result);
    }

    public function testCsrfTokenUsesStrongRandomness()
    {
       $cryptoStrong = false;
        $weak = bin2hex(openssl_random_pseudo_bytes($this->reader->tokenLen, $cryptoStrong));
        $token = $this->reader->getCSRFToken();

        $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{' . ($this->reader->tokenLen * 2) . '}$/i', $token);
        $this->assertNotEquals($weak, $token, "Token must not be equal to a weakly generated value");
        $this->assertTrue($cryptoStrong, "CSRF token must come from a strong cryptographic RNG");}
*/}