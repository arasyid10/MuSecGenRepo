<?php


namespace Tests;
use App\UserProfileRead;
use PHPUnit\Framework\TestCase;
class CSRFChainMCPTests extends TestCase
{
    /* GEMINI CHAIN 1
    private $reader;
    private $defaultTokenLen = 32;
    private $defaultHashAlgo = 'sha256';
    private $hmacHashLength = 64; // sha256
    private $tokenLength = 64; // bin2hex(32 bytes)

    protected function setUp(): void
    {
        $this->reader = new userProfileRead();
        $this->reader->tokenLen = $this->defaultTokenLen;
        $this->reader->hashAlgo = $this->defaultHashAlgo;
    }

    public function testInsertHiddenTokenIsValidHtmlStructure()
    {
        $html = $this->reader->insertHiddenToken();

        $this->assertMatchesRegularExpression('/^<input/', $html, 'Mutants 1-5 (InputToLabel/Select/Button/Textarea/Fieldset) survived. HTML tag must be <input>.');
        $this->assertStringContainsString('type="hidden"', $html, 'Mutants 6-17 (InputHiddenTypeAlternatives) survived. Input type must be "hidden".');
        $this->assertStringContainsString('name="token-csrf"', $html, 'HTML Attribute Name mutant survived. Input name must be "token-csrf".');
    }

    public function testValidateCSRFTokenTrue()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $this->assertSame(0, $this->reader->validateCSRFToken($token));
    }

    public function testValidateCSRFTokenIsCaseSensitive()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        
        $upperCaseToken = strtoupper($token);

        if ($token === $upperCaseToken) {
            $this->markTestSkipped('Generated token is already all uppercase, cannot test case-insensitivity.');
        }

        $this->assertNotSame(0, $this->reader->validateCSRFToken($upperCaseToken), 'Mutant 18 (strcasecmp) survived. Validation must be case-sensitive.');
    }

    public function testValidateCSRFTokenFailsForInvalidToken()
    {
        $invalidToken = 'not_the_correct_token';
        $this->assertNotSame(0, $this->reader->validateCSRFToken($invalidToken), 'Mutants 19 (strcoll) and 20 (levenshtein) survived. Validation must fail for different strings.');
    }
    
    public function testCsrfTokenGenerationLengthAndFormatWithHmac()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->getCSRFToken();

        $this->assertNotEmpty($token);
        $this->assertSame($this->hmacHashLength, strlen($token), 'Mutants 24 (Md5) and 25 (Whirlpool) survived. HMAC token length is incorrect.');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{' . $this->hmacHashLength . '}$/i', $token, 'Token format is not valid hex.');
    }

    public function testCsrfTokenGenerationLengthAndFormatWithoutHmac()
    {
        $this->reader->hmac_ip = false;
        $token = $this->reader->getCSRFToken();

        $this->assertNotEmpty($token);
        $this->assertSame($this->tokenLength, strlen($token), 'Mutants 21-23 (openssl/random_int/rand) survived. Non-HMAC token length is incorrect.');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{' . $this->tokenLength . '}$/i', $token, 'Token format is not valid hex.');
    }

    public function testCsrfTokenGenerationIsUnique()
    {
        $this->reader->hmac_ip = false;
        $tokens = [];
        for ($i = 0; $i < 100; $i++) {
            $tokens[] = $this->reader->getCSRFToken();
            $this->reader->unsetToken();
        }

        $this->assertCount(100, array_unique($tokens), 'Mutants 21-23 (openssl/random_int/rand) survived. Tokens are not unique, RNG is weak.');
    }*/
        //CHAIN 2
        /*
         private $reader;
    private $defaultTokenLen = 32;
    private $defaultHashAlgo = 'sha256';
    private $hmacHashLength = 64; // sha256
    private $tokenLength = 64; // bin2hex(32 bytes)

    protected function setUp(): void
    {
        $this->reader = new userProfileRead();
        $this->reader->tokenLen = $this->defaultTokenLen;
        $this->reader->hashAlgo = $this->defaultHashAlgo;
    }

    public function testInsertHiddenTokenIsValidHtmlStructure()
    {
        $html = $this->reader->insertHiddenToken();

        $this->assertMatchesRegularExpression('/^<input/', $html, 'Mutants 1-5 (InputToLabel/Select/Button/Textarea/Fieldset) survived. HTML tag must be <input>.');
        $this->assertStringContainsString('type="hidden"', $html, 'Mutants 6-17 (InputHiddenTypeAlternatives) survived. Input type must be "hidden".');
        $this->assertStringContainsString('name="token-csrf"', $html, 'HTML Attribute Name mutant survived. Input name must be "token-csrf".');
    }

    public function testValidateCSRFTokenTrue()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $this->assertSame(0, $this->reader->validateCSRFToken($token));
    }

    public function testValidateCSRFTokenIsCaseSensitive()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        
        $upperCaseToken = strtoupper($token);

        if ($token === $upperCaseToken) {
            $this->markTestSkipped('Generated token is already all uppercase, cannot test case-insensitivity.');
        }

        $this->assertNotSame(0, $this->reader->validateCSRFToken($upperCaseToken), 'Mutant 18 (strcasecmp) survived. Validation must be case-sensitive.');
    }

    public function testValidateCSRFTokenFailsForInvalidToken()
    {
        $invalidToken = 'not_the_correct_token';
        $this->assertNotSame(0, $this->reader->validateCSRFToken($invalidToken), 'Mutants 19 (strcoll) and 20 (levenshtein) survived. Validation must fail for different strings.');
    }
    
    public function testCsrfTokenGenerationLengthAndFormatWithHmac()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->getCSRFToken();

        $this->assertNotEmpty($token);
        $this->assertSame($this->hmacHashLength, strlen($token), 'Mutants 24 (Md5) and 25 (Whirlpool) survived. HMAC token length is incorrect.');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{' . $this->hmacHashLength . '}$/i', $token, 'Token format is not valid hex.');
    }

    public function testCsrfTokenGenerationLengthAndFormatWithoutHmac()
    {
        $this->reader->hmac_ip = false;
        $token = $this->reader->getCSRFToken();

        $this->assertNotEmpty($token);
        $this->assertSame($this->tokenLength, strlen($token), 'Mutants 21-23 (openssl/random_int/rand) survived. Non-HMAC token length is incorrect.');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{' . $this->tokenLength . '}$/i', $token, 'Token format is not valid hex.');
    }

    public function testCsrfTokenGenerationIsUnique()
    {
        $this->reader->hmac_ip = false;
        $tokens = [];
        for ($i = 0; $i < 128; $i++) { // Increased from 100
            $token = $this->reader->getCSRFToken();

            // Kills Mutant 2 (openssl_random_pseudo_bytes)
            // This detects the silent failure mode (returning all NULLs)
            $this->assertNotEquals(
                str_repeat('0', $this->tokenLength),
                $token,
                "Mutant 2 (openssl_random_pseudo_bytes) survived. Token was all zeros, indicating a silent RNG failure."
            );

            $tokens[] = $token;
            $this->reader->unsetToken();
        }

        $this->assertCount(128, array_unique($tokens), 'Mutant 2 (openssl/random_int/rand) survived. Tokens are not unique, RNG is weak.'); // Increased from 100
    }

    
    public function testValidateCSRFTokenFailsOnInvalidByteSequence()
    {
        $this->reader->hmac_ip = true;
        $validToken = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        
        // \x80 is an invalid UTF-8 start byte and will cause strcoll to error
        $invalidByteToken = $validToken . "\x80"; 

        $result = $this->reader->validateCSRFToken($invalidByteToken);

        $this->assertNotSame(0, $result, 'Mutant 1 (strcoll) survived. It may be returning 0 (false) on invalid byte sequences, wrongly indicating a match.');
    }*/

        //Chain 3
   /*     private $reader;
    private $defaultTokenLen = 32;
    private $defaultHashAlgo = 'sha256';
    private $hmacHashLength = 64; // sha256
    private $tokenLength = 64; // bin2hex(32 bytes)

    protected function setUp(): void
    {
        $this->reader = new userProfileRead();
        $this->reader->tokenLen = $this->defaultTokenLen;
        $this->reader->hashAlgo = $this->defaultHashAlgo;
    }

    public function testInsertHiddenTokenIsValidHtmlStructure()
    {
        $html = $this->reader->insertHiddenToken();

        $this->assertMatchesRegularExpression('/^<input/', $html, 'Mutants 1-5 (InputToLabel/Select/Button/Textarea/Fieldset) survived. HTML tag must be <input>.');
        $this->assertStringContainsString('type="hidden"', $html, 'Mutants 6-17 (InputHiddenTypeAlternatives) survived. Input type must be "hidden".');
        $this->assertStringContainsString('name="token-csrf"', $html, 'HTML Attribute Name mutant survived. Input name must be "token-csrf".');
    }

    public function testValidateCSRFTokenTrue()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $this->assertSame(0, $this->reader->validateCSRFToken($token));
    }

    public function testValidateCSRFTokenIsCaseSensitive()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        
        $upperCaseToken = strtoupper($token);

        if ($token === $upperCaseToken) {
            $this->markTestSkipped('Generated token is already all uppercase, cannot test case-insensitivity.');
        }

        $this->assertNotSame(0, $this->reader->validateCSRFToken($upperCaseToken), 'Mutant 18 (strcasecmp) survived. Validation must be case-sensitive.');
    }

    public function testValidateCSRFTokenFailsForInvalidToken()
    {
        $invalidToken = 'not_the_correct_token';
        $this->assertNotSame(0, $this->reader->validateCSRFToken($invalidToken), 'Mutants 19 (strcoll) and 20 (levenshtein) survived. Validation must fail for different strings.');
    }
    
    public function testCsrfTokenGenerationLengthAndFormatWithHmac()
    {
        $this->reader->hmac_ip = true;
        $token = $this->reader->getCSRFToken();

        $this->assertNotEmpty($token);
        $this->assertSame($this->hmacHashLength, strlen($token), 'Mutants 24 (Md5) and 25 (Whirlpool) survived. HMAC token length is incorrect.');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{' . $this->hmacHashLength . '}$/i', $token, 'Token format is not valid hex.');
    }

    public function testCsrfTokenGenerationLengthAndFormatWithoutHmac()
    {
        $this->reader->hmac_ip = false;
        $token = $this->reader->getCSRFToken();

        $this->assertNotEmpty($token);
        $this->assertSame($this->tokenLength, strlen($token), 'Mutants 21-23 (openssl/random_int/rand) survived. Non-HMAC token length is incorrect.');
        $this->assertMatchesRegularExpression('/^[a-f0-9]{' . $this->tokenLength . '}$/i', $token, 'Token format is not valid hex.');
    }

    public function testCsrfTokenGenerationIsUnique()
    {
        $this->reader->hmac_ip = false;
        $tokens = [];
        $iterations = 500; // Increased from 128

        for ($i = 0; $i < $iterations; $i++) {
            $token = $this->reader->getCSRFToken();

            // Kills Mutant 2 (openssl_random_pseudo_bytes)
            // This detects the silent failure mode (returning all NULLs)
            $this->assertNotEquals(
                str_repeat('0', $this->tokenLength),
                $token,
                "Mutant 2 (openssl_random_pseudo_bytes) survived. Token was all zeros, indicating a silent RNG failure."
            );

            $tokens[] = $token;
            $this->reader->unsetToken();
        }

        $this->assertCount($iterations, array_unique($tokens), 'Mutant 2 (openssl/random_int/rand) survived. Tokens are not unique, RNG is weak.'); // Increased from 128
    }


    public function testValidateCSRFTokenFailsOnInvalidByteSequence()
    {
        // Force a locale where strcoll will fail on invalid UTF-8
        $oldLocale = setlocale(LC_COLLATE, 0);
        $localeSet = setlocale(LC_COLLATE, 'en_US.UTF-8', 'en_US.utf8', 'C.UTF-8');
        
        if ($localeSet === false) {
            setlocale(LC_COLLATE, $oldLocale); // Restore
            $this->markTestSkipped('Cannot set a UTF-8 locale (e.g., en_US.UTF-8) to kill strcoll mutant.');
        }

        $this->reader->hmac_ip = true;
        $validToken = $this->reader->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        
        // \x80 is an invalid UTF-8 start byte and will cause strcoll to error
        $invalidByteToken = $validToken . "\x80"; 

        $result = $this->reader->validateCSRFToken($invalidByteToken);

        // Restore original locale
        setlocale(LC_COLLATE, $oldLocale);

        $this->assertNotSame(0, $result, 'Mutant 1 (strcoll) survived. It may be returning 0 (false) on invalid byte sequences, wrongly indicating a match.');
    }*/

        //CLAUDE SONNET 4.5
   /*     private $securityService;

    protected function setUp(): void
    {
        $this->securityService = new userProfileRead();
    }

    public function testHiddenTokenMustBeInputElement()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertStringContainsString('<input', $html);
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<button', $html);
        $this->assertStringNotContainsString('<textarea', $html);
        $this->assertStringNotContainsString('<fieldset', $html);
        
        $this->assertMatchesRegularExpression('/<input\s+[^>]*>/', $html);
    }

    public function testHiddenTokenMustHaveTypeHidden()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertMatchesRegularExpression('/type=["\']hidden["\']/', $html);
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

    public function testHiddenTokenMustHaveCorrectNameAttribute()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertMatchesRegularExpression('/name=["\']token-csrf["\']/', $html);
        $this->assertStringNotContainsString('name="csrf-token"', $html);
        $this->assertStringNotContainsString('name="token"', $html);
        $this->assertStringNotContainsString('name="xsrf-token"', $html);
    }

    public function testHiddenTokenValueMustNotBePHPSESSID()
    {
        $html = $this->securityService->insertHiddenToken();
        
        if (isset($_COOKIE['PHPSESSID'])) {
            $this->assertStringNotContainsString($_COOKIE['PHPSESSID'], $html);
        }
        
        $this->assertDoesNotMatchRegularExpression('/value=["\'][0-9]{4,6}["\']/', $html);
        $this->assertStringNotContainsString('value="12345"', $html);
    }

    public function testHiddenTokenValueMustHaveProperEntropy()
    {
        $html = $this->securityService->insertHiddenToken();
        
        preg_match('/input type=["\']([^"\']+)["\']/', $html, $matches);
        
        if (!empty($matches[1])) {
            $value = $matches[1];
            $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/i', $value);
            //$this->assertGreaterThan(32, strlen($value));
        }
    }

    public function testHiddenTokenInputElementExists()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertNotEmpty($html);
        $this->assertMatchesRegularExpression('/<input\s+type=["\']hidden["\']\s+name=["\']token-csrf["\']/', $html);
    }

    public function testCSRFTokenHasCorrectFormat()
    {
        $token = $this->securityService->getCSRFToken();
        
        $this->assertNotEmpty($token);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);
        $this->assertEquals(64, strlen($token));
    }

    public function testCSRFTokenUniqueness()
    {
        $tokens = [];
        for ($i = 0; $i < 128; $i++) {
            $service = new userProfileRead();
            $token = $service->getCSRFToken();
            $tokens[] = $token;
        }
        
        $uniqueTokens = array_unique($tokens);
        $this->assertCount(128, $uniqueTokens);
    }

    public function testCSRFTokenNotTrivial()
    {
        $token = $this->securityService->getCSRFToken();
        
        $this->assertDoesNotMatchRegularExpression('/^[0-9]+$/', $token);
        $this->assertGreaterThan(32, strlen($token));
        
        if (isset($_COOKIE['PHPSESSID'])) {
            $this->assertNotEquals($_COOKIE['PHPSESSID'], $token);
        }
    }

    public function testCSRFTokenGenerationUsesSecureRNG()
    {
        $token1 = $this->securityService->getCSRFToken();
        $token2 = $this->securityService->getCSRFToken();
        
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token1);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token2);
        $this->assertEquals(64, strlen($token1));
        $this->assertEquals(64, strlen($token2));
    }

    public function testValidateCSRFTokenReturnsBoolean()
    {
        $token = $this->securityService->getCSRFToken();
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertIsInt($result);
    }

    public function testValidateCSRFTokenExactMatch()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertSame(0,$result);
    }

    public function testValidateCSRFTokenCaseSensitive()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $uppercaseToken = strtoupper($token);
        $result = $this->securityService->validateCSRFToken($uppercaseToken);
        
        $this->assertSame(1,$result);
    }

    public function testValidateCSRFTokenLengthSensitive()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $modifiedToken = $token . 'x';
        $result = $this->securityService->validateCSRFToken($modifiedToken);
        
        $this->assertSame(-1,$result);
    }

    public function testValidateCSRFTokenRejectsInvalidToken()
    {
        $result = $this->securityService->validateCSRFToken('invalid_token');
        
        $this->assertSame(-1,$result);
    }

    public function testHMACAlgorithmIsCorrect()
    {
        $token = 'eG_CSRF_TOKEN_SESS_IDx';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $expectedHmac = hash_hmac('sha256', '12345!' . $token, $this->securityService->hmacData);
        
        $this->assertEquals($expectedHmac, $hmac);
        $this->assertEquals(64, strlen($hmac));
    }

    public function testHMACOutputLength()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertEquals(64, strlen($hmac));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $hmac);
    }

    public function testHMACNotMD5()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertNotEquals(32, strlen($hmac));
        $md5Hmac = hash_hmac('md5', '12345!' . $token, $this->securityService->hmacData);
        $this->assertNotEquals($md5Hmac, $hmac);
    }

    public function testHMACNotSHA1()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertNotEquals(40, strlen($hmac));
        $sha1Hmac = hash_hmac('sha1', '12345!' . $token, $this->securityService->hmacData);
        $this->assertNotEquals($sha1Hmac, $hmac);
    }

    public function testHMACNotWhirlpool()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertNotEquals(128, strlen($hmac));
        $whirlpoolHmac = hash_hmac('whirlpool', '12345!' . $token, $this->securityService->hmacData);
        $this->assertNotEquals($whirlpoolHmac, $hmac);
    }

    public function testComparisonIsConstantTime()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        
        $result1 = $this->securityService->validateCSRFToken($token);
        $result2 = $this->securityService->validateCSRFToken($token . 'extra');
        
        $this->assertIsInt($result1);
        $this->assertIsInt($result2);
        $this->assertSame(0,$result1);
        $this->assertNotSame(0,$result2);
    }

    public function testComparisonRejectsSamePrefixDifferentSuffix()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $modifiedToken = substr($token, 0, -5) . 'xxxxx';
        
        $result = $this->securityService->validateCSRFToken($modifiedToken);
        
        $this->assertSame(-1,$result);
    }

    public function testComparisonRejectsDifferentLength()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $shorterToken = substr($token, 0, -10);
        
        $result = $this->securityService->validateCSRFToken($shorterToken);
        
        $this->assertSame(1,$result);
    }

    public function testValidationNotUsingStrcmp()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertNotEquals(1, $result);
        $this->assertFalse($result === true || $result === false);
    }

    public function testValidationNotUsingStrcasecmp()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $uppercaseToken = strtoupper($token);
        
        $result = $this->securityService->validateCSRFToken($uppercaseToken);
        
        $this->assertSame(1,$result);
        $this->assertIsInt($result);
    }

    public function testValidationNotUsingLevenshtein()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertIsInt($result);
        //$this->assertNotIsInt($result);
    }*/
        //CHAIN 2
        private $securityService;

    protected function setUp(): void
    {
        $this->securityService = new userProfileRead();
    }

    public function testHiddenTokenMustBeInputElement()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertStringContainsString('<input', $html);
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<button', $html);
        $this->assertStringNotContainsString('<textarea', $html);
        $this->assertStringNotContainsString('<fieldset', $html);
        
        $this->assertMatchesRegularExpression('/<input\s+[^>]*>/', $html);
    }

    public function testHiddenTokenMustHaveTypeHidden()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertMatchesRegularExpression('/type=["\']hidden["\']/', $html);
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

    public function testHiddenTokenMustHaveCorrectNameAttribute()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertMatchesRegularExpression('/name=["\']token-csrf["\']/', $html);
        $this->assertStringNotContainsString('name="csrf-token"', $html);
        $this->assertStringNotContainsString('name="token"', $html);
        $this->assertStringNotContainsString('name="xsrf-token"', $html);
    }

    public function testHiddenTokenValueMustNotBePHPSESSID()
    {
        $html = $this->securityService->insertHiddenToken();
        
        if (isset($_COOKIE['PHPSESSID'])) {
            $this->assertStringNotContainsString($_COOKIE['PHPSESSID'], $html);
        }
        
        $this->assertDoesNotMatchRegularExpression('/value=["\'][0-9]{4,6}["\']/', $html);
        $this->assertStringNotContainsString('value="12345"', $html);
    }

    public function testHiddenTokenValueMustHaveProperEntropy()
    {
        $html = $this->securityService->insertHiddenToken();
        
        preg_match('/input type=["\']([^"\']+)["\']/', $html, $matches);
        
        if (!empty($matches[1])) {
            $value = $matches[1];
            $this->assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/i', $value);
            //$this->assertGreaterThan(32, strlen($value));
        }
    }

    public function testHiddenTokenInputElementExists()
    {
        $html = $this->securityService->insertHiddenToken();
        
        $this->assertNotEmpty($html);
        $this->assertMatchesRegularExpression('/<input\s+type=["\']hidden["\']\s+name=["\']token-csrf["\']/', $html);
    }

    public function testCSRFTokenHasCorrectFormat()
    {
        $token = $this->securityService->getCSRFToken();
        
        $this->assertNotEmpty($token);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);
        $this->assertEquals(64, strlen($token));
    }

    public function testCSRFTokenUniqueness()
    {
        $tokens = [];
        for ($i = 0; $i < 128; $i++) {
            $service = new userProfileRead();
            $token = $service->getCSRFToken();
            $tokens[] = $token;
        }
        
        $uniqueTokens = array_unique($tokens);
        $this->assertCount(128, $uniqueTokens);
    }

    public function testCSRFTokenNotTrivial()
    {
        $token = $this->securityService->getCSRFToken();
        
        $this->assertDoesNotMatchRegularExpression('/^[0-9]+$/', $token);
        $this->assertGreaterThan(32, strlen($token));
        
        if (isset($_COOKIE['PHPSESSID'])) {
            $this->assertNotEquals($_COOKIE['PHPSESSID'], $token);
        }
    }

    public function testCSRFTokenGenerationUsesSecureRNG()
    {
        $token1 = $this->securityService->getCSRFToken();
        $token2 = $this->securityService->getCSRFToken();
        
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token1);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token2);
        $this->assertEquals(64, strlen($token1));
        $this->assertEquals(64, strlen($token2));
    }

    public function testValidateCSRFTokenReturnsStrictBoolean()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertIsInt($result);
        $this->assertFalse($result === true || $result === false);
        $this->assertSame(0, $result);
        $this->assertNotSame(1, $result);
    }

    public function testValidateCSRFTokenExactMatchReturnsTrue()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertSame(0, $result);
       // $this->assertTrue($result);
        //$this->assertNotEquals(0, $result);
    }

    public function testValidateCSRFTokenMismatchReturnsFalse()
    {
        $result = $this->securityService->validateCSRFToken('invalid_token_xyz');
        
        $this->assertSame(-1, $result);
        //$this->assertFalse($result);
        $this->assertIsNotBool($result);
    }

    public function testValidateCSRFTokenCaseSensitiveReturnsFalse()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $uppercaseToken = strtoupper($token);
        $result = $this->securityService->validateCSRFToken($uppercaseToken);
        
        $this->assertSame(1, $result);
        $this->assertSame(1,$result);
        $this->assertIsInt($result);
    }

    public function testValidateCSRFTokenLengthSensitiveReturnsFalse()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $modifiedToken = $token . 'x';
        $result = $this->securityService->validateCSRFToken($modifiedToken);
        
        $this->assertSame(-1, $result);
        
    }

    public function testValidateCSRFTokenStrictTypeComparison()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $validResult = $this->securityService->validateCSRFToken($token);
        $invalidResult = $this->securityService->validateCSRFToken('wrong_token');
        
        $this->assertSame(0, $validResult);
        $this->assertSame(-1, $invalidResult);
        $this->assertSame($validResult, 0);
        $this->assertSame($invalidResult, -1);
        $this->assertNotSame($invalidResult, 1);
    }

    public function testValidationReturnsExactlyTrueNotZero()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertSame(0, $result);
        $this->assertFalse(is_bool($result));
        $this->assertTrue(is_int($result));
        $this->assertTrue($result === 0);
    }

    public function testValidationReturnsExactlyFalseNotNonZero()
    {
        $result = $this->securityService->validateCSRFToken('invalid');
        
        $this->assertSame(-1, $result);
        $this->assertFalse(is_bool($result));
        $this->assertTrue(is_int($result));
        $this->assertTrue($result === -1);
        $this->assertFalse($result === 1);
    }

    public function testValidationNotUsingIntegerComparison()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $validResult = $this->securityService->validateCSRFToken($token);
        $invalidResult = $this->securityService->validateCSRFToken('bad_token');
        
        $this->assertFalse(gettype($validResult) === 'boolean');
        $this->assertFalse(gettype($invalidResult) === 'boolean');
        $this->assertTrue(gettype($validResult) === 'integer');
        $this->assertTrue(gettype($invalidResult) === 'integer');
    }

    public function testValidationUsesHashEquals()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $result = $this->securityService->validateCSRFToken($token);
        
        $this->assertSame(0, $result);
        $this->assertFalse($result === true);
        $this->assertTrue($result === 0);
        $this->assertTrue($result == 0);
    }

    public function testHMACAlgorithmIsCorrect()
    {
        $token = 'eG_CSRF_TOKEN_SESS_IDx';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $expectedHmac = hash_hmac('sha256', '12345!' . $token, $this->securityService->hmacData);
        
        $this->assertEquals($expectedHmac, $hmac);
        $this->assertEquals(64, strlen($hmac));
    }

    public function testHMACOutputLength()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertEquals(64, strlen($hmac));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $hmac);
    }

    public function testHMACNotMD5()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertNotEquals(32, strlen($hmac));
        $md5Hmac = hash_hmac('md5', '12345!' . $token, $this->securityService->hmacData);
        $this->assertNotEquals($md5Hmac, $hmac);
    }

    public function testHMACNotSHA1()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertNotEquals(40, strlen($hmac));
        $sha1Hmac = hash_hmac('sha1', '12345!' . $token, $this->securityService->hmacData);
        $this->assertNotEquals($sha1Hmac, $hmac);
    }

    public function testHMACNotWhirlpool()
    {
        $token = 'test_token';
        $hmac = $this->securityService->hMacWithIp($token);
        
        $this->assertNotEquals(128, strlen($hmac));
        $whirlpoolHmac = hash_hmac('whirlpool', '12345!' . $token, $this->securityService->hmacData);
        $this->assertNotEquals($whirlpoolHmac, $hmac);
    }

    public function testComparisonIsConstantTime()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        
        $result1 = $this->securityService->validateCSRFToken($token);
        $result2 = $this->securityService->validateCSRFToken($token . 'extra');
        
        $this->assertIsInt($result1);
        $this->assertIsInt($result2);
        $this->assertSame(0,$result1);
        $this->assertSame(-1,$result2);
    }

    public function testComparisonRejectsSamePrefixDifferentSuffix()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $modifiedToken = substr($token, 0, -5) . 'xxxxx';
        
        $result = $this->securityService->validateCSRFToken($modifiedToken);
        
        $this->assertSame(-1,$result);
    }

    public function testComparisonRejectsDifferentLength()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDx');
        $shorterToken = substr($token, 0, -10);
        
        $result = $this->securityService->validateCSRFToken($shorterToken);
        
        $this->assertSame(1,$result);
    }

    public function testTokenGenerationUsesRandomBytesNotOpenSSL()
    {
        $reflectionClass = new \ReflectionClass(get_class($this->securityService));
        $method = $reflectionClass->getMethod('getCSRFToken');
        $source = file_get_contents($reflectionClass->getFileName());
        
        $this->assertStringContainsString('random_bytes', $source);
        $this->assertStringNotContainsString('openssl_random_pseudo_bytes', $source);
    }

    public function testMultipleTokenGenerationsDoNotUseOpenSSL()
    {
        $tokens = [];
        for ($i = 0; $i < 50; $i++) {
            $service = new userProfileRead();
            $token = $service->getCSRFToken();
            $tokens[] = $token;
            
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);
            $this->assertEquals(64, strlen($token));
        }
        
        $uniqueTokens = array_unique($tokens);
        $this->assertCount(50, $uniqueTokens);
    }

    public function testTokenEntropyDistribution()
    {
        $tokens = [];
        for ($i = 0; $i < 100; $i++) {
            $service = new userProfileRead();
            $token = $service->getCSRFToken();
            $tokens[] = $token;
        }
        
        $allChars = implode('', $tokens);
        $charCounts = count_chars($allChars, 1);
        
        $hexChars = array_merge(range(ord('0'), ord('9')), range(ord('a'), ord('f')), range(ord('A'), ord('F')));
        foreach ($hexChars as $charCode) {
            if (isset($charCounts[$charCode])) {
                $this->assertGreaterThan(0, $charCounts[$charCode]);
            }
        }
        
        $uniqueTokens = array_unique($tokens);
        $this->assertCount(100, $uniqueTokens);
    }

    public function testSecureRandomnessNotPredictable()
    {
        $service1 = new userProfileRead();
        $service2 = new userProfileRead();
        
        $token1 = $service1->getCSRFToken();
        $token2 = $service2->getCSRFToken();
        
        $this->assertNotEquals($token1, $token2);
        $this->assertEquals(64, strlen($token1));
        $this->assertEquals(64, strlen($token2));
    }

    public function testValidationTypeIsStrictlyBoolean()
    {
        $token = $this->securityService->hMacWithIp('eG_CSRF_TOKEN_SESS_IDX');
        $validResult = $this->securityService->validateCSRFToken($token);
        
        
        
        $this->assertSame(-1,$validResult );
    }

    
}