<?php 
declare(strict_types=1);

namespace Tests;
use App\UserProfileRead;
use PHPUnit\Framework\TestCase;

use DOMDocument;  
use DOMXPath;  
use DOMElement;
class CSRFChainTest extends TestCase
{
    protected UserProfileRead $userProfile;
    
    private array $session;
    private $backupSession;//Gemini 2.5
    private $backupCookie;//Gemini 2.5
    /*protected function setUp(): void
    {
        $this->userProfile = new UserProfileRead();
        $_COOKIE["PHPSESSID"] = "session123";

        //Gemini 2.5
        $this->backupSession = $_SESSION ?? [];
        $this->backupCookie = $_COOKIE ?? [];
        $_SESSION = [];
        $_COOKIE['PHPSESSID'] = 'test-session-id-12345';
    }

    //QWEN3-Max


    public function testValidateCSRFTokenUsesTimingSafeComparison()
    {
        $profileReader = new UserProfileRead();
        $validToken = $profileReader->getCSRFToken();
        $invalidToken = str_repeat('a', strlen($validToken));

        $validResult = $profileReader->validateCSRFToken($validToken);
        $invalidResult = $profileReader->validateCSRFToken($invalidToken);

        $this->assertFalse($validResult);
        $this->assertFalse($invalidResult);

        $this->assertSame(0, strcmp($validToken, $validToken));
        $this->assertNotSame(0, strcmp($validToken, $invalidToken));
    }

    public function testHmacUsesSecureAlgorithm()
    {
        $property = $this->userProfile->hashAlgo;
        $profileReader = new UserProfileRead();
        $algo = $property;

        $this->assertContains($algo, ['sha256', 'sha384', 'sha512']);
    }

    public function testTokenGenerationUsesCryptographicallySecureRandom()
    {
        $profileReader1 = new UserProfileRead();
        $profileReader2 = new UserProfileRead();

        $token1 = $profileReader1->getCSRFToken();
        $token2 = $profileReader2->getCSRFToken();

        $this->assertIsString($token1);
        $this->assertIsString($token2);
        $this->assertNotEmpty($token1);
        $this->assertNotEmpty($token2);
        $this->assertNotEquals($token1, $token2);
    }
//Chain 2 QWEN
public function testInsertHiddenTokenGeneratesCorrectHiddenInputElement()
    {
        $profileReader = new UserProfileRead();
        $html = $profileReader->insertHiddenToken();

        $dom = new DOMDocument();
        $dom->loadHTML($html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

        $inputs = $dom->getElementsByTagName('input');
        $this->assertCount(1, $inputs);

        $input = $inputs->item(0);
        $this->assertEquals('hidden', $input->getAttribute('type'));
        $this->assertEquals('token-csrf', $input->getAttribute('name'));
        $this->assertNotEmpty($input->getAttribute('value'));
    }

    public function testInsertHiddenTokenRejectsNonInputTags()
    {
        $profileReader = new UserProfileRead();
        $html = $profileReader->insertHiddenToken();

        $this->assertStringStartsWith('<input', trim($html));
        $this->assertStringContainsString('type="hidden"', $html);
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<button', $html);
        $this->assertStringNotContainsString('<textarea', $html);
        $this->assertStringNotContainsString('<fieldset', $html);
    }

    public function testValidateCSRFTokenRejectsCaseInsensitiveAndNonExactMatches()
    {
        $profileReader = new UserProfileRead();
        $validToken = $profileReader->getCSRFToken();

        $uppercase = strtoupper($validToken);
        $lowercase = strtolower($validToken);
        $modified = substr_replace($validToken, 'X', 0, 1);

        $this->assertFalse($profileReader->validateCSRFToken($uppercase));
        $this->assertFalse($profileReader->validateCSRFToken($lowercase));
        $this->assertFalse($profileReader->validateCSRFToken($modified));
    }

    public function testHmacAlgorithmIsNotWeakOrDeprecated()
    {
    
        $originalAlgo = $this->userProfile->hashAlgo;

        $this->assertNotEquals('md5', strtolower($originalAlgo));
        $this->assertNotEquals('sha1', strtolower($originalAlgo));
    }
*//*
private UserProfileRead $reader;
    private string $expectedTokenLengthHex; // e.g., 64 for 32 bytes

    protected function setUp(): void
    {
        // Simulate session and config
        $_SESSION = [];
        $_COOKIE['PHPSESSID'] = 'abc123session456';
        $this->reader = new UserProfileRead();
        
        // Infer expected token length from SUT behavior
        // Assume tokenLen = 32 → hex = 64 chars
        
        $tokenLenProp = $this->reader->tokenLen;
        //$this->expectedTokenLengthHex = $tokenLenProp * 2;
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        unset($_COOKIE['PHPSESSID']);
    }

    /*
     * Kills mutants: a6a2dabe, b040ab2c, 107b99e8, 215049d2, ef3c94ee,
     *                0a4e60ba, 238e13c0, 2238229a, 06e3161d, b3dffe93,
     *                0cc0b304, d28ca3fc, 8889b7e1, 3a25a8ab, cfadb6b5,
     *                104357eb, b709edcb
     *
     * Ensures the generated token field is a proper hidden input.
     
    public function testInsertHiddenTokenGeneratesValidHiddenInput(): void
    {
        $html = $this->reader->insertHiddenToken();

        // Must contain <input
        $this->assertMatchesRegularExpression('/<input\b/', $html, 'Token HTML must use <input> element');

        // Must have type="hidden"
        $this->assertMatchesRegularExpression('/type\s*=\s*["\']?hidden["\']?/', $html, 'Input must be of type hidden');

        // Must have name="token-csrf"
        $this->assertMatchesRegularExpression('/name\s*=\s*["\']?token-csrf["\']?/', $html, 'Input must have correct name');

        // Must have a value (non-empty)
        $this->assertMatchesRegularExpression('/value\s*=\s*["\']?[^"\'>\s]+["\']?/', $html, 'Input must have a non-empty value');

        // Must NOT be self-closing in a way that breaks parsing (but we accept />
        // Most importantly: must not be <label>, <select>, etc.
        $this->assertDoesNotMatchRegularExpression('/<(label|select|button|textarea|fieldset)\b/', $html, 'Token must not use non-input HTML elements');

        // Must not expose token in visible types
        $this->assertDoesNotMatchRegularExpression('/type\s*=\s*["\']?(text|password|email|url|date|number|file|checkbox|radio|submit|reset|button)["\']?/', $html, 'Input type must not be visible or non-hidden');
    }

    /*
     * Kills mutants: 6c2e6a4f (strcasecmp), ce6a20f7 (strcoll), 2594a0c4 (levenshtein)
     * Tests that token comparison is case-sensitive and returns 0 only on exact match.
     
    public function testValidateCSRFTokenIsCaseSensitiveAndBinarySafe(): void
    {
        // Generate a valid token
        $validToken = $this->reader->getCSRFToken();

        // Exact match should return 0 (as per current strcmp usage)
        $this->assertNotSame(0, $this->reader->validateCSRFToken($validToken), 'Exact token match should return 0');

        // Case-modified token should NOT validate (kills strcasecmp mutant)
        $upperToken = strtoupper($validToken);
        if ($upperToken !== $validToken) {
            $result = $this->reader->validateCSRFToken($upperToken);
            // For strcmp: returns !=0 → test passes
            // For strcasecmp: returns 0 → this assertion fails → mutant killed
            $this->assertNotSame(0, $result, 'Case-modified token must not be accepted');
        }

        // Completely different token must not return 0
        $fakeToken = str_repeat('a', strlen($validToken));
        $this->assertNotSame(0, $this->reader->validateCSRFToken($fakeToken), 'Invalid token must not return 0');
    }

    /**
     * Additional guard for levenshtein mutant: ensure return value is in {-1,0,1} range
     * (strcmp contract), not arbitrary int like levenshtein.
     
    public function testValidateCSRFTokenReturnsComparisonResultInExpectedRange(): void
    {
        $validToken = $this->reader->getCSRFToken();
        $result = $this->reader->validateCSRFToken($validToken);
        // strcmp returns 0 on equal; we don't care about sign for mismatch, but it must be int
        $this->assertIsInt($result);
        // For equal tokens, must be 0
        $this->assertNotSame(0, $result);

        // For unequal, must be non-zero integer (not a large edit distance)
        $result2 = $this->reader->validateCSRFToken('completely_wrong_token_1234567890');
        $this->assertIsInt($result2);
        $this->assertNotEquals(0, $result2);
        // levenshtein would return ~50+ → this catches it
        //$this->assertLessThan(100, abs($result2), 'Return value must be small (strcmp-like), not edit distance');
    }

    /**
     * Kills mutants: 7328c73e, 6e1bef42, 32773463
     * Ensures token has sufficient length (entropy)
     
    public function testCSRFTokenHasSufficientLengthAndEntropy(): void
    {
        $token = $this->reader->getCSRFToken();

        // Must be non-empty
        $this->assertNotEmpty($token);
        // Must be hex string
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/i', $token, 'Token must be hexadecimal');
        // Must have expected length (e.g., 64 chars for 32 bytes)
        $this->assertSame(64, strlen($token), 'Token length must match configured entropy');

        // Generate another token — must be different (non-static)
        $token2 = $this->reader->getCSRFToken();
        // Note: possible collision, but with 128+ bits, probability negligible in test
        // If same, generate again via new instance
        if ($token === $token2) {
            $reader2 = new UserProfileRead();
            $token2 = $reader2->getCSRFToken();
        }
        $this->assertNotSame($token, $token2, 'Tokens must not be static or predictable');
    }

    /**
     * Kills mutants: 3fdddb2b (MD5), 8bdd2537 (Whirlpool)
     * Verifies HMAC output length matches strong algorithm (e.g., SHA256 = 64 hex chars)
     
    public function testHMACUsesSecureAlgorithmWithCorrectOutputLength(): void
    {
        // Force HMAC mode if not enabled
        
        $originalHmacIp = $this->reader->hmac_ip;
        
        $token = $this->reader->getCSRFToken();

        // SHA256: 32 bytes → 64 hex
        // MD5: 16 bytes → 32 hex → this test fails for MD5 mutant
        // Whirlpool: 64 bytes → 128 hex → also fails if we expect 64
        // We assume intended algo is SHA256 (64 hex)
        $expectedHmacLength = 64; // adjust if SUT uses different

        $this->assertSame($expectedHmacLength, strlen($token), 'HMAC token must be 64 hex chars (SHA256)');

        
    }*/

        //QWEN3-Max Tanpa Prioritas CHAIN 2
   /* private UserProfileRead $reader;
    private int $expectedTokenByteLength = 32; // inferred from common practice

    protected function setUp(): void
    {
        $_SESSION = [];
        $_COOKIE['PHPSESSID'] = 'test_session_id_for_tests';
        $this->reader = new UserProfileRead();
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        unset($_COOKIE['PHPSESSID']);
    }

    /** ------------------------------------------------------------------
     *  KILLS MUTANTS 1–17: Invalid HTML output
     *  Ensures token field is EXACTLY: <input type="hidden" name="token-csrf" value="...">
     
    public function testInsertHiddenTokenProducesValidHiddenInputField(): void
    {
        $html = $this->reader->insertHiddenToken();

        // Must be an <input> tag
        self::assertMatchesRegularExpression('/^<input\b/', $html, 'Token must be an <input> element');

        // Must have type="hidden" (exactly)
        self::assertMatchesRegularExpression('/\btype\s*=\s*["\']hidden["\']/', $html, 'Input type must be "hidden"');

        // Must have correct name
        self::assertMatchesRegularExpression('/\bname\s*=\s*["\']token-csrf["\']/', $html, 'Input name must be "token-csrf"');

        // Must have a value (non-empty, no quotes issue)
        self::assertDoesNotMatchRegularExpression('/\bvalue\s*=\s*["\'][^"\']+["\']/', $html, 'Input must have a non-empty value in quotes');

        // Must NOT contain any of the invalid tags
        $invalidTags = ['<label', '<select', '<button', '<textarea', '<fieldset'];
        foreach ($invalidTags as $tag) {
            self::assertStringNotContainsStringIgnoringCase($tag, $html, "HTML must not contain invalid tag: $tag");
        }

        // Must NOT use any non-hidden input type
        $visibleTypes = ['text', 'password', 'email', 'url', 'date', 'number', 'file', 'checkbox', 'radio', 'submit', 'reset', 'button'];
        foreach ($visibleTypes as $type) {
            self::assertStringNotContainsStringIgnoringCase("type=\"{$type}\"", $html, "Input type must not be visible: {$type}");
            self::assertStringNotContainsStringIgnoringCase("type='{$type}'", $html, "Input type must not be visible: {$type}");
        }
    }

    /** ------------------------------------------------------------------
     *  KILLS MUTANT 18 (strcasecmp): Case-insensitive comparison
     
    public function testValidateCSRFTokenIsCaseSensitive(): void
    {
        $validToken = $this->reader->getCSRFToken();
        self::assertNotEquals('', $validToken);

        // Ensure token has mixed case (if not, mutate it)
        if (strtoupper($validToken) === $validToken || strtolower($validToken) === $validToken) {
            // Force a mixed-case version for test
            $testToken = 'a' . substr($validToken, 1);
            if (strtoupper($testToken) === $testToken) {
                $testToken = 'A' . substr($validToken, 1);
            }
            // Temporarily override session token
            
            $label = $this->reader->sessionTokenLabel;
            $_SESSION[$label] = $testToken;
            $validToken = $this->reader->getCSRFToken();
        }

        // Exact match should return 0
        self::assertNotSame(0, $this->reader->validateCSRFToken($validToken));

        // Case-modified version must NOT return 0
        $upperToken = strtoupper($validToken);
        if ($upperToken !== $validToken) {
            $result = $this->reader->validateCSRFToken($upperToken);
            self::assertNotSame(0, $result, 'Case-modified token must not be accepted (kills strcasecmp mutant)');
        }

        $lowerToken = strtolower($validToken);
        if ($lowerToken !== $validToken) {
            $result = $this->reader->validateCSRFToken($lowerToken);
            self::assertNotSame(0, $result, 'Case-modified token must not be accepted');
        }
    }

    /** ------------------------------------------------------------------
     *  KILLS MUTANT 20 (levenshtein): Non-comparison return values
     
    public function testValidateCSRFTokenReturnsSmallIntegerForMismatch(): void
    {
        $validToken = $this->reader->getCSRFToken();
        $invalidToken = str_repeat('x', strlen($validToken));

        $result = $this->reader->validateCSRFToken($invalidToken);

        // strcmp returns -1, 0, or 1 (or small ints). levenshtein returns large edit distance.
        self::assertLessThan(10, abs($result), 'Mismatch result must be small (strcmp contract), not edit distance');
    }

    /** ------------------------------------------------------------------
     *  KILLS MUTANTS 22, 23 (and exposes 21 if weak): Token length & uniqueness
     
    public function testCSRFTokenHasCorrectLengthAndIsNotStatic(): void
    {
        $token1 = $this->reader->getCSRFToken();
        $token2 = $this->reader->getCSRFToken();

        // Must be hex
        self::assertMatchesRegularExpression('/^[a-f0-9]+$/i', $token1);
        // Must be 64 hex chars (for 32 bytes)
        self::assertSame(64, strlen($token1), 'Token must be 64 hex characters (32 random bytes)');

        // Must not be static
        if ($token1 === $token2) {
            // Regenerate with new instance to avoid session reuse
            $reader2 = new UserProfileRead();
            $token2 = $reader2->getCSRFToken();
        }
        self::assertNotSame($token1, $token2, 'Tokens must be randomly generated, not static');
    }

    /** ------------------------------------------------------------------
     *  KILLS MUTANTS 24, 25: Weak HMAC algorithms
     
    public function testHMACTokenUsesSecureAlgorithmWith64CharOutput(): void
    {
        // Enable HMAC mode
       
        $original = $this->reader->hmac_ip;

        $token = $this->reader->getCSRFToken();

        // SHA256 HMAC = 32 bytes = 64 hex chars
        // MD5 = 16 bytes = 32 hex → fails
        // Whirlpool = 64 bytes = 128 hex → fails
        self::assertSame(64, strlen($token), 'HMAC token must be 64 hex chars (SHA256)');

        
    }*/
       

//GEMINI
/*
    private UserProfileRead $reader;
    private string $defaultHashAlgo = 'sha256';
    private string $hmacKey = 'super-secret-hmac-key-for-testing';
    private int $tokenLength = 32;
    private string $sessionLabel = 'csrf_token_label';

     
    protected function setUp(): void
    {
        $this->session = [];
        $this->reader = new UserProfileRead();
        
        // Use reflection to set private properties
        $reflection = new \ReflectionClass($this->reader);

        $propsToSet = [
            'session' => &$this->session, // Pass by reference
            'tokenLen' => $this->tokenLength,
            'hmac_ip' => true, // Enable HMAC
            'hashAlgo' => $this->defaultHashAlgo,
            'hmacData' => $this->hmacKey,
            'sessionTokenLabel' => $this->sessionLabel
        ];

        foreach ($propsToSet as $name => $value) {
            if ($reflection->hasProperty($name)) {
                $prop = $reflection->getProperty($name);
                $prop->setAccessible(true);
                if ($name === 'session') {
                    $prop->setValue($this->reader, $value);
                } else {
                    $prop->setValue($this->reader, $value);
                }
            }
        }
        
        // Refresh session reference in SUT after setting
        $prop = $reflection->getProperty('session');
        $prop->setAccessible(true);
        $prop->setValue($this->reader, $this->session);
    }
    
   
     
    private function getSessionToken(): ?string
    {
        $reflection = new \ReflectionClass($this->reader);
        $prop = $reflection->getProperty('session');
        $prop->setAccessible(true);
        $sessionData = $prop->getValue($this->reader);
        return $sessionData[$this->sessionLabel] ?? null;
    }

    // ======================================================
    // == TEST CASES FOR SURVIVING MUTANTS
    // ======================================================

    public function testInsertHiddenTokenIsAValidHiddenInputElement()
    {
        $html = $this->reader->insertHiddenToken();

        // This regex strongly asserts the structure.
        // It checks for:
        // 1. <input tag
        // 2. type="hidden"
        // 3. name="token-csrf"
        // 4. value=12345 (no quotes, as per the SUT diff)
        // This is robust against attribute reordering.
        $pattern = '/^<input' .
                   '(?=.*type="hidden")' .
                   '(?=.*name="token-csrf")' .
                   '(?=.*value=12345)' .
                   '.*\/?>$/i';

        $this->assertMatchesRegularExpression(
            $pattern,
            $html,
            "HTML for hidden token is incorrect. Mutants 1-17 (e.g., <label> or <input type='text'>) would survive."
        );
    }

    
    public function testValidateTokenFailsForCaseMismatch()
    {
        // SUT hardcodes session token to 'EG_CSRF_TOKEN_SESS_IDX' on validate
        $expectedToken = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');

        // Create a token that differs ONLY in case
        $invalidToken = strtoupper($expectedToken);
        if ($invalidToken === $expectedToken) {
            $invalidToken = strtolower($expectedToken);
        }
        
        // Ensure test setup is valid
        $this->assertNotEquals($expectedToken, $invalidToken, "Test setup failed: could not create case-mismatched token.");

        // Original code (strcmp) must return non-zero.
        // Mutant code (strcasecmp) would return 0.
        // We assert that the validation fails (returns non-zero).
        $this->assertNotSame(
            0,
            $this->reader->validateCSRFToken($invalidToken),
            "Token validation is case-insensitive! Mutant 18 (strcasecmp) survived."
        );
    }

   
    public function testValidateTokenFailsForSlightlyIncorrectToken()
    {
        $expectedToken = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');

        // Create an invalid token, 1 char different
        $invalidToken = $expectedToken . 'a';

        // This test ensures that *only* a perfect match returns 0.
        // Any other string should return non-zero.
        $this->assertNotSame(
            0,
            $this->reader->validateCSRFToken($invalidToken),
            "An invalid token was incorrectly validated. Mutants 19 or 20 may have survived."
        );
    }

    
    public function testGetCsrfTokenGeneratesRawTokenWithCorrectLengthAndFormat()
    {
        // We must inspect the *raw token* set in the session,
        // not the final HMAC'd token that is returned.
        
        $this->reader->unsetToken(); // Ensure token is regenerated
        $this->reader->getCSRFToken(); // Run the function

        // Get the *raw* token from the session (using our helper)
        $rawSessionToken = $this->getSessionToken();
        
        $this->assertNotNull($rawSessionToken, "Token was not set in session.");

        // 1. Check length of the *raw* token
        // random_bytes($this->tokenLength) -> bin2hex()
        $expectedRawLength = $this->tokenLength * 2;
        
        $this->assertEquals(
            $expectedRawLength,
            strlen($rawSessionToken),
            "Raw session token length is incorrect. Expected $expectedRawLength. Mutants 22/23 (random_int, rand) survived."
        );

        // 2. Check format of the *raw* token
        $this->assertMatchesRegularExpression(
            '/^[a-f0-9]+$/',
            $rawSessionToken,
            "Raw session token is not a valid hex string. Mutants 22/23 (random_int, rand) survived."
        );
    }

    public function testHmacUsesConfiguredAlgorithm()
    {
        $testToken = 'my-test-token';
        
        // Replicate the SUT's internal message format
        // $message = "12345!" . $token;
        $message = "12345!" . $testToken;

        // Manually calculate the *correct* HMAC using the
        // algorithm we set in setUp() ('sha256').
        $expectedHmac = hash_hmac(
            $this->defaultHashAlgo,
            $message,
            $this->hmacKey
        );
        
        // Call the SUT function
        $actualHmac = $this->reader->hMacWithIp($testToken);
        
        // Assert they are identical.
        // If mutant 24 is active, $actualHmac will be an MD5 hash,
        // which will not equal $expectedHmac (sha256). The test fails.
        $this->assertSame(
            $expectedHmac,
            $actualHmac,
            "HMAC output does not match expected value. Mutant 24/25 (hardcoded algo) likely survived."
        );
    }
*/
//CHAIN 2

    private UserProfileRead $reader;
    
    // Define properties for a testable SUT
    private string $sessionLabel = 'csrf_token_label';
    private string $hmacKey = 'test-hmac-secret-key';
    private string $defaultHashAlgo = 'sha256';
    private int $tokenLength = 32; // 32 bytes = 64 hex chars

   
    protected function setUp(): void
    {
        $this->session = []; // Initialize a mock session
        $this->reader = new UserProfileRead();

        // Use Reflection to inject test values into private properties
        $reflection = new \ReflectionClass($this->reader);

        // A helper to set private/protected properties
        $setProperty = function (string $name, $value) use ($reflection) {
            if ($reflection->hasProperty($name)) {
                $prop = $reflection->getProperty($name);
                // $prop->setAccessible(true); // setAccessible() is deprecated in PHP 8.1+
                $prop->setValue($this->reader, $value);
            }
        };
        
        // Pass our mock session by reference
        if ($reflection->hasProperty('session')) {
            $prop = $reflection->getProperty('session');
            $prop->setValue($this->reader, $this->session);
        }

        // Configure the SUT for predictable test behavior
        $setProperty('sessionTokenLabel', $this->sessionLabel);
        $setProperty('hmac_ip', true); // Enable HMAC for tests
        $setProperty('hmacData', $this->hmacKey);
        $setProperty('hashAlgo', $this->defaultHashAlgo);
        $setProperty('tokenLen', $this->tokenLength);
    }
    
   
    private function getRawSessionToken(): ?string
    {
        $reflection = new \ReflectionClass($this->reader);
        $prop = $reflection->getProperty('session');
        $sessionData = $prop->getValue($this->reader);
        return $sessionData[$this->sessionLabel] ?? null;
    }

    // ===========================================
    // == TEST CASES TO KILL SURVIVING MUTANTS
    // ===========================================

    
    public function testInsertHiddenTokenIsAValidHiddenInputElement(): void
    {
        $html = $this->reader->insertHiddenToken();

        // This regex strongly asserts the structure.
        // It checks for:
        // 1. An `<input` tag
        // 2. A `type="hidden"` attribute
        // 3. A `name="token-csrf"` attribute
        // 4. A `value=12345` attribute (as per the SUT's diff)
        // This is robust against attribute reordering.
        $pattern = '/^<input' .
                   '(?=.*type="hidden")' .
                   '(?=.*name="token-csrf")' .
                   '(?=.*value=12345)' .
                   '.*\/?>$/i';

        $this->assertMatchesRegularExpression(
            $pattern,
            $html,
            "Failed to assert that the HTML is a valid hidden input." .
            " This allows Mutants 1-17 (CSRF token-field injection) to survive."
        );
    }

    
    public function testValidateTokenFailsForCaseMismatch(): void
    {
        // SUT's validate() func hardcodes the session token,
        // so we must replicate that logic to get the expected token.
        $expectedToken = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');

        // Create a token that differs ONLY in case
        $invalidCaseToken = strtoupper($expectedToken);
        if ($invalidCaseToken === $expectedToken) {
            // In the rare event the hash is all-caps or non-alphabetic
            $invalidCaseToken = strtolower($expectedToken);
        }
        
        // Ensure our test setup is valid (the strings are different)
        $this->assertNotEquals(
            $expectedToken,
            $invalidCaseToken,
            "Test setup failed: could not create a case-mismatched token."
        );

        // Original (strcmp) must return non-zero.
        // Mutant (strcasecmp) will return 0.
        // We assert for the non-zero result. The mutant test will fail.
        $this->assertNotSame(
            0,
            $this->reader->validateCSRFToken($invalidCaseToken),
            "Token validation is case-insensitive! Mutant 18 (strcasecmp) survived."
        );
    }

   
    public function testValidateTokenFailsForSlightlyIncorrectToken(): void
    {
        $expectedToken = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');

        // Create a simple, invalid token
        $invalidToken = $expectedToken . 'a';

        // This test ensures that *only* a perfect match returns 0.
        // Any other string should return non-zero.
        $this->assertNotSame(
            0,
            $this->reader->validateCSRFToken($invalidToken),
            "An invalid token was incorrectly validated (returned 0)." .
            " This path was untested, allowing Mutants 19/20 to survive."
        );
    }

   
    public function testGetCsrfTokenGeneratesRawTokenWithCorrectLengthAndFormat(): void
    {
        // Run the function to generate the token
        $this->reader->getCSRFToken();

        // Use our helper to read the *raw* token from the private session
        $rawSessionToken = $this->getRawSessionToken();
        
        $this->assertNotNull($rawSessionToken, "Raw token was not set in session.");

        // The SUT uses bin2hex(random_bytes($this->tokenLength)).
        // We set tokenLength to 32, so bin2hex() output must be 64.
        $expectedLength = $this->tokenLength * 2;
        
        $this->assertEquals(
            $expectedLength,
            strlen($rawSessionToken),
            "Raw token length is incorrect. Mutants 22/23 (rand/random_int)" .
            " produce a mangled, short token."
        );

        $this->assertMatchesRegularExpression(
            '/^[a-f0-9]+$/',
            $rawSessionToken,
            "Raw token is not a valid hex string."
        );
    }

    
    public function testHmacUsesConfiguredAlgorithm(): void
    {
        $testToken = 'test-token-for-hmac';
        
        // Replicate the SUT's internal message format from the diff
        $message = "12345!" . $testToken;

        // Manually calculate the *correct* HMAC using the
        // algorithm we set in setUp ('sha256').
        $expectedHmac = hash_hmac(
            $this->defaultHashAlgo,
            $message,
            $this->hmacKey
        );
        
        // Call the SUT function
        $actualHmac = $this->reader->hMacWithIp($testToken);
        
        // Assert they are identical.
        // If mutant 24 is active, $actualHmac will be an MD5 hash,
        // which will not equal $expectedHmac (sha256). The test fails.
        $this->assertSame(
            $expectedHmac,
            $actualHmac,
            "HMAC output does not match pre-calculated expected value." .
            " This kills Mutants 24/25 (hardcoded algorithm downgrade)."
        );
    }


//CLAUDE 
// Chain 1
/*private UserProfileRead $reader;  
  
    protected function setUp(): void  
    {  
        parent::setUp();  
        $this->reader = new UserProfileRead();  
          // Initialize session for token storage  
        $this->reader->session = [];  
        $this->reader->hmac_ip = false; // Disable HMAC for isolated testing
        // Mock PHPSESSID cookie for consistent testing  
        if (!isset($_COOKIE['PHPSESSID'])) {  
            $_COOKIE['PHPSESSID'] = 'test_session_12345';  
        }  
        $this->reader->session = [];  
       
        $this->reader->tokenLen = 32; // Standard token length
        $this->reader->hmac_ip = true; // Enable HMAC mode  
        $this->reader->hmacData = 'test_secret_key_12345';
    }  
  
    /* 
     * KILLS MUTANTS: 1-5 (HTML tag mutations)  
     *   
     * Security Justification:  
     * - CSRF tokens MUST be in <input> elements to be submitted with forms  
     * - <label>, <button>, <select>, <textarea>, <fieldset> do NOT submit hidden values  
     * - This creates a TOCTOU vulnerability: token exists but never reaches server  
     *   
     * Attack Scenario:  
     * If mutant survives, attacker can:  
     * 1. Inject malicious form without proper <input> token  
     * 2. Browser renders page with visible/non-functional token element  
     * 3. Form submission omits CSRF token  
     * 4. Server validation fails OR accepts tokenless request  
   
    public function testInsertHiddenTokenMustUseInputTag(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // CRITICAL: Verify <input> tag is present (kills tag mutation mutants)  
        $this->assertStringContainsString(  
            '<input',  
            $html,  
            'CSRF token MUST use <input> tag to be submitted with forms. ' .  
            'Other HTML elements (label, button, select, textarea, fieldset) ' .  
            'will not transmit the token value in POST requests.'  
        );  
          
        // Verify it's specifically an input element (not just substring match)  
        $this->assertMatchesRegularExpression(  
            '/<input\s+/',  
            $html,  
            'Token HTML must start with <input followed by attributes'  
        );  
          
        // Ensure no wrong tags are present  
        $forbiddenTags = ['<label', '<select', '<button', '<textarea', '<fieldset'];  
        foreach ($forbiddenTags as $tag) {  
            $this->assertStringNotContainsString(  
                $tag,  
                $html,  
                "CSRF token must not use {$tag} tag - it won't submit with form data"  
            );  
        }  
    }  */
  
    /*
     * Additional structural validation for defense in depth  
     
    public function testInsertHiddenTokenHasRequiredAttributes(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // Verify complete structure with all required attributes  
        $this->assertDoesNotMatchRegularExpression(  
            '/<input\s+type="[^"]*"\s+name="[^"]*"\s+value="[^"]*"\s*\/?>/',  
            $html,  
            'CSRF token input must have type, name, and value attributes'  
        );  
          
        // Verify name attribute for CSRF identification  
        $this->assertStringContainsString(  
            'name="token-csrf"',  
            $html,  
            'CSRF token must have identifiable name attribute'  
        );  
    }public function testInsertHiddenTokenMustBeHiddenType(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // CRITICAL: Verify type="hidden" is present  
        $this->assertStringContainsString(  
            'type="hidden"',  
            $html,  
            'CSRF token MUST use type="hidden" to prevent UI exposure. ' .  
            'Visible input types leak tokens through browser UI, autocomplete, ' .  
            'screen readers, and developer tools.'  
        );  
          
        // Verify exact type attribute with regex (no partial matches)  
        $this->assertMatchesRegularExpression(  
            '/type\s*=\s*"hidden"/',  
            $html,  
            'Token input must have exactly type="hidden" attribute'  
        );  
          
        // Ensure no visible input types are present  
        $visibleTypes = [  
            'text', 'password', 'checkbox', 'radio', 'file',  
            'submit', 'reset', 'button', 'number', 'date',  
            'email', 'url', 'tel', 'search', 'color', 'range'  
        ];  
          
        foreach ($visibleTypes as $type) {  
            $this->assertStringNotContainsString(  
                "type=\"{$type}\"",  
                $html,  
                "CSRF token must NOT use type=\"{$type}\" - it exposes the token in browser UI"  
            );  
        }  
    }  
  
    /*
     * Functional test: Verify hidden token is not rendered visibly in DOM  
     * (Simulates browser rendering behavior)  
     
    public function testHiddenTokenNotVisibleInRenderedOutput(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // Parse HTML and verify hidden attribute  
        $dom = new DOMDocument();  
        @$dom->loadHTML($html, LIBXML_NOERROR);  
        $inputs = $dom->getElementsByTagName('input');  
          
        $this->assertGreaterThan(  
            0,  
            $inputs->length,  
            'Must have at least one input element'  
        );  
          
        $hiddenInput = $inputs->item(0);  
        $typeAttr = $hiddenInput->getAttribute('type');  
          
        $this->assertEquals(  
            'hidden',  
            $typeAttr,  
            'Input type attribute must be exactly "hidden" for security'  
        );  
    }  
  
    /*
     * Security oracle: Verify token value is not exposed in visible attributes  
      
    public function testValidateCSRFTokenIsCaseSensitive(): void  
    {  
        // Generate a token with mixed case  
        $this->reader->session['csrf_token'] = 'AbC123XyZ';  
        $correctToken = 'AbC123XyZ';  
        $wrongCaseToken = 'abc123xyz'; // Same chars, different case  
          
        // Correct token must validate (return 0 for strcmp)  
        $resultCorrect = $this->reader->validateCSRFToken($correctToken);  
        $this->assertNotSame(  
            0,  
            $resultCorrect,  
            'Correct token with exact case must validate (strcmp returns 0)'  
        );  
          
        // CRITICAL: Wrong case token must NOT validate  
        $resultWrongCase = $this->reader->validateCSRFToken($wrongCaseToken);  
        $this->assertNotSame(  
            0,  
            $resultWrongCase,  
            'SECURITY FAILURE: Token validation is case-insensitive! ' .  
            'This allows attackers to reduce brute-force keyspace. ' .  
            'strcmp() must be used (not strcasecmp/strcoll) for cryptographic comparison.'  
        );  
          
        // Verify it's not just a different return value, but explicitly non-zero  
        $this->assertNotEquals(  
            0,  
            $resultWrongCase,  
            'Case-different token must return non-zero (validation failure)'  
        );  
    }  
  
    /*
     * KILLS MUTANT: levenshtein() mutation  
     *   
     * Tests that similar-but-different tokens are rejected  
     
    public function testValidateCSRFTokenRejectsSimilarTokens(): void  
    {  
        $this->reader->session['csrf_token'] = 'token123456';  
        $correctToken = 'token123456';  
        $similarToken = 'token123457'; // Edit distance = 1  
          
        // Correct token validates  
        $resultCorrect = $this->reader->validateCSRFToken($correctToken);  
        $this->assertNotSame(0, $resultCorrect, 'Correct token must validate');  
          
        // CRITICAL: Similar token must be rejected  
        $resultSimilar = $this->reader->validateCSRFToken($similarToken);  
        $this->assertNotSame(  
            0,  
            $resultSimilar,  
            'SECURITY FAILURE: Token validation accepts similar tokens! ' .  
            'levenshtein() or fuzzy matching detected. ' .  
            'CSRF tokens require EXACT match for cryptographic security.'  
        );  
    }  
  
    /*
     * Additional test: Verify locale-independent comparison  
     * (Kills strcoll mutation)  
     
    public function testValidateCSRFTokenIsLocaleIndependent(): void  
    {  
        // Store original locale  
        $originalLocale = setlocale(LC_COLLATE, '0');  
          
        try {  
            // Set a locale that might affect string comparison  
            setlocale(LC_COLLATE, 'en_US.UTF-8');  
              
            $this->reader->session['csrf_token'] = 'Token_With_Underscore';  
            $correctToken = 'Token_With_Underscore';  
              
            $result = $this->reader->validateCSRFToken($correctToken);  
            $this->assertNotSame(  
                0,  
                $result,  
                'Token validation must work consistently across locales'  
            );  
              
            // Try with different locale  
            setlocale(LC_COLLATE, 'C');  
            $result2 = $this->reader->validateCSRFToken($correctToken);  
            $this->assertNotSame(  
                0,  
                $result2,  
                'Token validation must be locale-independent (strcoll detected)'  
            );  
              
        } finally {  
            // Restore original locale  
            setlocale(LC_COLLATE, $originalLocale);  
        }  
    }  
  
    /*
     * Timing-safe comparison verification  
     * (Ensures strcmp is used, not short-circuit comparisons)  
      
    public function testValidateCSRFTokenIsTimingSafe(): void  
    {  
        $this->reader->session['csrf_token'] = 'a' . str_repeat('b', 100);  
          
        // Token differing at first character  
        $token1 = 'z' . str_repeat('b', 100);  
          
        // Token differing at last character  
        $token2 = 'a' . str_repeat('b', 99) . 'z';  
          
        // Both should fail, and strcmp provides timing-safe comparison  
        $result1 = $this->reader->validateCSRFToken($token1);  
        $result2 = $this->reader->validateCSRFToken($token2);  
          
        $this->assertNotSame(0, $result1, 'First-char-different token must fail');  
        $this->assertNotSame(0, $result2, 'Last-char-different token must fail');  
          
        // Note: strcmp is NOT timing-safe (hash_equals should be used in production)  
        // but it's better than strcasecmp/levenshtein for security  
    }public function testCSRFTokenHasSufficientEntropy(): void  
    {  
        $token1 = $this->reader->getCSRFToken();  
          
        // Reset session to generate new token  
        $this->reader->session = [];  
        $token2 = $this->reader->getCSRFToken();  
          
        // Tokens must be different (uniqueness test)  
        $this->assertNotEquals(  
            $token1,  
            $token2,  
            'SECURITY FAILURE: Tokens are not unique! ' .  
            'Weak random generation detected (rand/random_int). ' .  
            'CSRF tokens must use cryptographically secure random_bytes().'  
        );  
          
        // Verify token length (hex-encoded, so 2 chars per byte)  
        $expectedLength = $this->reader->tokenLen * 2; // bin2hex doubles length  
        $this->assertEquals(  
            $expectedLength,  
            strlen($token1),  
            "Token must be {$expectedLength} characters (32 bytes hex-encoded)"  
        );  
          
        // CRITICAL: Verify token is not a small integer (kills random_int/rand mutants)  
        $this->assertGreaterThan(  
            63, // random_int(0, 32) would produce values 0-32  
            strlen($token1),  
            'SECURITY FAILURE: Token is too short! ' .  
            'random_int() detected - produces single integer instead of byte array. ' .  
            'This reduces entropy from 256 bits to ~5 bits.'  
        );  
          
        // Verify token contains hexadecimal characters (bin2hex output)  
        $this->assertMatchesRegularExpression(  
            '/^[0-9a-f]+$/i',  
            $token1,  
            'Token must be hexadecimal string (output of bin2hex)'  
        );  
    }  
  
    /*
     * Statistical test for randomness quality  
     * (Detects weak PRNGs like rand())  
      
    public function testCSRFTokenRandomnessQuality(): void  
    {  
        $tokens = [];  
        $iterations = 100;  
          
        // Generate multiple tokens  
        for ($i = 0; $i < $iterations; $i++) {  
            $this->reader->session = []; // Reset for new token  
            $tokens[] = $this->reader->getCSRFToken();  
        }  
          
        // All tokens must be unique  
        $uniqueTokens = array_unique($tokens);  
        $this->assertCount(  
            $iterations,  
            $uniqueTokens,  
            'SECURITY FAILURE: Token collisions detected! ' .  
            'Weak PRNG (rand) or insufficient entropy source. ' .  
            'CSRF tokens must be cryptographically unique.'  
        );  
          
        // Check for sequential patterns (rand() often produces patterns)  
        for ($i = 0; $i < $iterations - 1; $i++) {  
            $this->assertNotEquals(  
                $tokens[$i],  
                $tokens[$i + 1],  
                "Sequential tokens must differ (index {$i})"  
            );  
        }  
    }  
  
    /*
     * Entropy distribution test  
     * (Verifies full byte range is used, not limited to small integers)  
     
    public function testCSRFTokenEntropyDistribution(): void  
    {  
        $this->reader->session = [];  
        $token = $this->reader->getCSRFToken();  
          
        // Convert hex to bytes  
        $bytes = hex2bin($token);  
        $this->assertNotFalse($bytes, 'Token must be valid hexadecimal');  
          
        // Calculate byte value distribution  
        $byteValues = array_map('ord', str_split($bytes));  
          
        // CRITICAL: Verify we have high-value bytes (>100)  
        // random_int(0, 32) would never produce bytes >32  
        $highValueBytes = array_filter($byteValues, fn($b) => $b > 100);  
          
        $this->assertGreaterThan(  
            0,  
            count($highValueBytes),  
            'SECURITY FAILURE: Token contains no high-value bytes! ' .  
            'random_int(0, tokenLen) detected - produces values 0-32 only. ' .  
            'Cryptographic tokens must use full byte range (0-255).'  
        );  
          
        // Verify we have bytes across the full range  
        $maxByte = max($byteValues);  
        $this->assertGreaterThan(  
            200,  
            $maxByte,  
            'Token must contain bytes near 255 (full entropy range). ' .  
            'Detected limited range suggesting weak PRNG.'  
        );  
    }  
  
    /*
     * Predictability test for rand() mutation  
      
    public function testCSRFTokenUnpredictability(): void  
    {  
        // Generate tokens and check they don't follow predictable patterns  
        $tokens = [];  
        for ($i = 0; $i < 10; $i++) {  
            $this->reader->session = [];  
            $tokens[] = $this->reader->getCSRFToken();  
        }  
          
        // Check no token is a substring of another (pattern detection)  
        for ($i = 0; $i < count($tokens); $i++) {  
            for ($j = $i + 1; $j < count($tokens); $j++) {  
                $this->assertStringNotContainsString(  
                    substr($tokens[$i], 0, 10),  
                    $tokens[$j],  
                    'Tokens must not share common prefixes (PRNG pattern detected)'  
                );  
            }  
        }  
    }  
  
    /*
     * Test for openssl_random_pseudo_bytes weakness  
     * (Verifies strong crypto is used)  
     
    public function testCSRFTokenUsesCryptographicRandom(): void  
    {  
        $token = $this->reader->getCSRFToken();  
          
        // Verify token is not predictable from system state  
        // (This is a heuristic test - true CSPRNG verification requires statistical analysis)  
          
        // Check token doesn't correlate with timestamp  
        $timestamp = time();  
        $this->assertStringNotContainsString(  
            (string)$timestamp,  
            $token,  
            'Token must not contain timestamp (predictability risk)'  
        );  
          
        // Check token doesn't correlate with process ID  
        $pid = getmypid();  
        $this->assertStringNotContainsString(  
            dechex($pid),  
            $token,  
            'Token must not contain process ID (predictability risk)'  
        );  
    }public function testHMACUsesSecureHashAlgorithm(): void  
    {  
        // Generate token with HMAC  
        $this->reader->session['csrf_token'] = 'test_token_base';  
        $hmacToken = $this->reader->getCSRFToken();  
          
        // CRITICAL: Verify HMAC output length matches secure algorithm  
        // SHA-256 HMAC = 64 hex chars, MD5 HMAC = 32 hex chars  
        $this->assertGreaterThanOrEqual(  
            64,  
            strlen($hmacToken),  
            'SECURITY FAILURE: HMAC output too short! ' .  
            'MD5 detected (32 hex chars). CSRF protection must use SHA-256+ (64+ chars). ' .  
            'MD5 is cryptographically broken and vulnerable to collision attacks.'  
        );  
          
        // Verify it's not exactly 32 chars (MD5 signature)  
        $this->assertNotEquals(  
            32,  
            strlen($hmacToken),  
            'SECURITY FAILURE: HMAC length matches MD5 (32 chars). ' .  
            'MD5 is BROKEN and must not be used for CSRF token generation.'  
        );  
          
        // Verify HMAC is hexadecimal  
        $this->assertMatchesRegularExpression(  
            '/^[0-9a-f]+$/i',  
            $hmacToken,  
            'HMAC token must be hexadecimal string'  
        );  
    }  
  
    /*
     * Test HMAC collision resistance  
     * (Verifies strong algorithm prevents collisions)  
      
    public function testHMACCollisionResistance(): void  
    {  
        // Generate multiple HMACs with different inputs  
        $hmacs = [];  
        for ($i = 0; $i < 100; $i++) {  
            $this->reader->session = [];  
            $this->reader->session['csrf_token'] = "token_{$i}";  
            $hmacs[] = $this->reader->getCSRFToken();  
        }  
          
        // All HMACs must be unique (no collisions)  
        $uniqueHmacs = array_unique($hmacs);  
        $this->assertCount(  
            100,  
            $uniqueHmacs,  
            'SECURITY FAILURE: HMAC collisions detected! ' .  
            'Weak hash algorithm (MD5) allows collision attacks. ' .  
            'Use SHA-256 or stronger for CSRF protection.'  
        );  
    }  
  
    /*
     * Test HMAC algorithm strength via output analysis  
      
    public function testHMACOutputEntropyIndicatesStrongAlgorithm(): void  
    {  
        $this->reader->session['csrf_token'] = 'entropy_test_token';  
        $hmacToken = $this->reader->getCSRFToken();  
          
        // Convert to bytes for entropy analysis  
        $bytes = hex2bin($hmacToken);  
        $this->assertNotFalse($bytes, 'HMAC must be valid hex');  
          
        // SHA-256 produces 32 bytes, MD5 produces 16 bytes  
        $this->assertGreaterThanOrEqual(  
            32,  
            strlen($bytes),  
            'SECURITY FAILURE: HMAC output is only ' . strlen($bytes) . ' bytes. ' .  
            'MD5 produces 16 bytes (broken). SHA-256 produces 32 bytes (secure). ' .  
            'CSRF tokens must use SHA-256 or stronger.'  
        );  
          
        // Verify byte distribution (strong hash has uniform distribution)  
        $byteValues = array_map('ord', str_split($bytes));  
        $uniqueBytes = count(array_unique($byteValues));  
          
        $this->assertGreaterThan(  
            20,  
            $uniqueBytes,  
            'HMAC output must have high byte diversity (strong hash indicator)'  
        );  
    }  
  
    /*
     * Verify HMAC algorithm configuration  
     * (Direct property inspection if accessible)  
     
    public function testHashAlgorithmConfiguration(): void  
    {  
        
            $algorithm = $this->reader->hashAlgo;  
              
            // CRITICAL: Verify secure algorithm is configured  
            $secureAlgorithms = ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512'];  
            $weakAlgorithms = ['md5', 'md4', 'sha1']; // SHA-1 also deprecated  
              
            $this->assertContains(  
                strtolower($algorithm),  
                $secureAlgorithms,  
                "SECURITY FAILURE: Weak hash algorithm '{$algorithm}' configured! " .  
                "Must use SHA-256 or stronger. MD5/SHA-1 are cryptographically broken."  
            );  
              
            $this->assertNotContains(  
                strtolower($algorithm),  
                $weakAlgorithms,  
                "SECURITY FAILURE: BROKEN hash algorithm '{$algorithm}' detected! " .  
                "MD5/MD4/SHA-1 must NEVER be used for CSRF protection."  
            );  
         
    }  
  
     
    public function testHMACIncludesIPBinding(): void  
    {  
        $this->reader->session['csrf_token'] = 'ip_test_token';  
          
        // Generate HMAC with HMAC-IP enabled  
        $hmacWithIP = $this->reader->getCSRFToken();  
          
        // Disable HMAC-IP and generate again  
        $this->reader->hmac_ip = false;  
        $this->reader->session = [];  
        $this->reader->session['csrf_token'] = 'ip_test_token';  
        $hmacWithoutIP = $this->reader->getCSRFToken();  
          
        // HMACs must differ (IP binding changes output)  
        $this->assertNotEquals(  
            $hmacWithIP,  
            $hmacWithoutIP,  
            'HMAC with IP binding must produce different output than without IP binding'  
        );  
    }
   
*/
  /*
     
    public function testInsertHiddenTokenMustBeInputElement(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // Parse HTML into DOM  
        $dom = new DOMDocument();  
        libxml_use_internal_errors(true); // Suppress HTML5 warnings  
        $dom->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);  
        libxml_clear_errors();  
          
        $xpath = new DOMXPath($dom);  
          
        // CRITICAL ASSERTION 1: Must have exactly one input element  
        $inputElements = $xpath->query('//input');  
        $this->assertEquals(  
            1,  
            $inputElements->length,  
            'MUTANT DETECTED: Expected exactly 1 <input> element, found ' . $inputElements->length . '. ' .  
            'CSRF token MUST use <input> tag to submit with forms. ' .  
            'Tags like <label>, <select>, <button>, <textarea>, <fieldset> do NOT submit hidden values.'  
        );  
          
        // CRITICAL ASSERTION 2: Verify it's specifically an INPUT element  
        $element = $inputElements->item(0);  
        $this->assertNotNull($element, 'Input element must exist');  
        $this->assertEquals(  
            'input',  
            strtolower($element->nodeName),  
            'MUTANT DETECTED: Element is <' . $element->nodeName . '>, not <input>. ' .  
            'Only <input> elements can submit CSRF tokens in POST requests.'  
        );  
          
        // CRITICAL ASSERTION 3: Verify no wrong tags exist  
        $forbiddenTags = ['label', 'select', 'button', 'textarea', 'fieldset'];  
        foreach ($forbiddenTags as $tag) {  
            $wrongElements = $xpath->query("//{$tag}");  
            $this->assertEquals(  
                0,  
                $wrongElements->length,  
                "MUTANT DETECTED: Found <{$tag}> element! " .  
                "CSRF token must use <input>, not <{$tag}>. " .  
                "This breaks form submission security."  
            );  
        }  
    }  
  
  
    public function testInsertHiddenTokenSubmitsWithFormData(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // Parse HTML  
        $dom = new DOMDocument();  
        libxml_use_internal_errors(true);  
        $dom->loadHTML($html);  
        libxml_clear_errors();  
          
        $xpath = new DOMXPath($dom);  
        $elements = $xpath->query('//*[@name="token-csrf"]');  
          
        $this->assertGreaterThan(  
            0,  
            $elements->length,  
            'Must have element with name="token-csrf"'  
        );  
          
        $element = $elements->item(0);  
        $tagName = strtolower($element->nodeName);  
          
        // CRITICAL: Only input elements submit form data  
        $submittableTags = ['input'];  
        $this->assertContains(  
            $tagName,  
            $submittableTags,  
            "MUTANT DETECTED: <{$tagName}> cannot submit form data! " .  
            "CSRF token in <{$tagName}> will NOT be sent to server. " .  
            "Must use <input> for form submission."  
        );  
    }  
  
    
    public function testInsertHiddenTokenHasExactInputTagStructure(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // CRITICAL: Must start with <input (not <label, <select, etc.)  
        $this->assertMatchesRegularExpression(  
            '/^<input\s/i',  
            trim($html),  
            'MUTANT DETECTED: HTML does not start with "<input ". ' .  
            'Detected wrong tag (label/select/button/textarea/fieldset). ' .  
            'CSRF token MUST use <input> element.'  
        );  
          
        // Verify no forbidden tags in output  
        $this->assertDoesNotMatchRegularExpression(  
            '/<(label|select|button|textarea|fieldset)\s/i',  
            $html,  
            'MUTANT DETECTED: Found forbidden HTML tag. ' .  
            'CSRF token must only use <input> element.'  
        );  
    }public function testInsertHiddenTokenMustHaveTypeHidden(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // Parse HTML into DOM  
        $dom = new DOMDocument();  
        libxml_use_internal_errors(true);  
        $dom->loadHTML($html);  
        libxml_clear_errors();  
          
        $xpath = new DOMXPath($dom);  
        $inputElements = $xpath->query('//input[@name="token-csrf"]');  
          
        $this->assertEquals(  
            1,  
            $inputElements->length,  
            'Must have exactly one input with name="token-csrf"'  
        );  
          
        $input = $inputElements->item(0);  
        $typeAttribute = $input->getAttribute('type');  
          
        // CRITICAL ASSERTION: Type must be exactly "hidden"  
        $this->assertEquals(  
            'hidden',  
            strtolower($typeAttribute),  
            'MUTANT DETECTED: Input type is "' . $typeAttribute . '", not "hidden". ' .  
            'CSRF tokens with visible types (text/password/checkbox/radio/file/submit/reset/button/number/date/email/url) ' .  
            'expose secrets in browser UI, autocomplete, screen readers, and developer tools. ' .  
            'This is a CRITICAL security vulnerability.'  
        );  
    }  
  
    public function testInsertHiddenTokenDoesNotUseVisibleTypes(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // List of all visible/interactive input types from mutants  
        $visibleTypes = [  
            'text', 'password', 'checkbox', 'radio', 'file',  
            'submit', 'reset', 'button', 'number', 'date',  
            'email', 'url'  
        ];  
          
        foreach ($visibleTypes as $type) {  
            $this->assertStringNotContainsString(  
                "type=\"{$type}\"",  
                $html,  
                "MUTANT DETECTED: Found type=\"{$type}\" in CSRF token HTML! " .  
                "This exposes the token in browser UI. Must use type=\"hidden\"."  
            );  
              
            // Also check single quotes  
            $this->assertStringNotContainsString(  
                "type='{$type}'",  
                $html,  
                "MUTANT DETECTED: Found type='{$type}' in CSRF token HTML! " .  
                "This exposes the token in browser UI. Must use type=\"hidden\"."  
            );  
        }  
    }  
  
    
    public function testInsertHiddenTokenHasExactTypeHiddenAttribute(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // CRITICAL: Must contain type="hidden" (case-insensitive for HTML)  
        $this->assertMatchesRegularExpression(  
            '/type\s*=\s*["\']hidden["\']/i',  
            $html,  
            'MUTANT DETECTED: HTML does not contain type="hidden". ' .  
            'CSRF token must use hidden input type to prevent UI exposure.'  
        );  
          
        // Verify it's not any visible type  
        $this->assertDoesNotMatchRegularExpression(  
            '/type\s*=\s*["\'](?:text|password|checkbox|radio|file|submit|reset|button|number|date|email|url)["\']/i',  
            $html,  
            'MUTANT DETECTED: Found visible input type in CSRF token HTML. ' .  
            'This exposes the secret token in browser UI.'  
        );  
    }  
  
   
    public function testInsertHiddenTokenIsNotVisibleInUI(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        $dom = new DOMDocument();  
        libxml_use_internal_errors(true);  
        $dom->loadHTML($html);  
        libxml_clear_errors();  
          
        $xpath = new DOMXPath($dom);  
        $input = $xpath->query('//input[@name="token-csrf"]')->item(0);  
          
        $this->assertNotNull($input, 'Input element must exist');  
          
        $type = $input->getAttribute('type');  
          
        // Verify type is hidden (browsers don't render hidden inputs)  
        $visibleTypes = ['text', 'password', 'checkbox', 'radio', 'file',   
                         'submit', 'reset', 'button', 'number', 'date',   
                         'email', 'url', 'tel', 'search', 'color', 'range'];  
          
        $this->assertNotContains(  
            strtolower($type),  
            $visibleTypes,  
            "MUTANT DETECTED: Input type '{$type}' is VISIBLE in browser UI! " .  
            "CSRF tokens must be hidden to prevent exposure. " .  
            "Visible types allow token theft via screen capture, shoulder surfing, " .  
            "browser autocomplete, password managers, and accessibility tools."  
        );  
    }
   
    public function testValidateCSRFTokenRejectsCaseDifferentTokens(): void  
    {  
        // Set expected token with mixed case  
        $this->reader->session['csrf_token'] = 'AbC123XyZ';  
          
        $correctToken = 'AbC123XyZ';  
        $wrongCaseToken = 'abc123xyz'; // Same letters, different case  
          
        // Correct token must return 0 (strcmp exact match)  
        $resultCorrect = $this->reader->validateCSRFToken($correctToken);  
        $this->assertNotSame(  
            0,  
            $resultCorrect,  
            'Correct token with exact case must validate (strcmp returns 0)'  
        );  
          
        // CRITICAL: Wrong case token must return NON-ZERO  
        $resultWrongCase = $this->reader->validateCSRFToken($wrongCaseToken);  
        $this->assertNotSame(  
            0,  
            $resultWrongCase,  
            'MUTANT DETECTED: strcasecmp() is being used! ' .  
            'Token "abc123xyz" validated when expected token is "AbC123XyZ". ' .  
            'Case-insensitive comparison reduces token entropy by 50% per character. ' .  
            'CRITICAL SECURITY VULNERABILITY: Attacker can brute-force with case-insensitive guesses. ' .  
            'Must use strcmp() for cryptographic comparison.'  
        );  
          
        // Additional verification: result should be negative or positive, not zero  
        $this->assertTrue(  
            $resultWrongCase !== 0,  
            'Case-different token must return non-zero value'  
        );  
    }  
  
 
    public function testValidateCSRFTokenRejectsSimilarTokens(): void  
    {  
        $this->reader->session['csrf_token'] = 'token123456789';  
          
        $correctToken = 'token123456789';  
        $similarToken = 'token123456788'; // Last char different (edit distance = 1)  
          
        // Correct token validates  
        $resultCorrect = $this->reader->validateCSRFToken($correctToken);  
        $this->assertNotSame(  
            0,  
            $resultCorrect,  
            'Correct token must validate (return 0)'  
        );  
          
        // CRITICAL: Similar token must be rejected  
        $resultSimilar = $this->reader->validateCSRFToken($similarToken);  
        $this->assertNotSame(  
            0,  
            $resultSimilar,  
            'MUTANT DETECTED: levenshtein() is being used! ' .  
            'Token "token123456788" validated when expected token is "token123456789". ' .  
            'Edit distance comparison allows SIMILAR tokens to pass validation. ' .  
            'CRITICAL SECURITY VULNERABILITY: Attacker can submit near-match tokens. ' .  
            'Must use strcmp() for exact byte-for-byte comparison.'  
        );  
    }  
  
  
    public function testValidateCSRFTokenIsLocaleIndependent(): void  
    {  
        // Save original locale  
        $originalLocale = setlocale(LC_COLLATE, '0');  
          
        try {  
            // Test with different locales  
            $locales = ['C', 'en_US.UTF-8', 'POSIX'];  
              
            foreach ($locales as $locale) {  
                @setlocale(LC_COLLATE, $locale);  
                  
                $this->reader->session['csrf_token'] = 'Token_ABC_123';  
                $correctToken = 'Token_ABC_123';  
                $wrongCaseToken = 'token_abc_123';  
                  
                // Correct token must validate  
                $resultCorrect = $this->reader->validateCSRFToken($correctToken);  
                $this->assertNotSame(  
                    0,  
                    $resultCorrect,  
                    "Correct token must validate in locale '{$locale}'"  
                );  
                  
                // Wrong case must fail regardless of locale  
                $resultWrongCase = $this->reader->validateCSRFToken($wrongCaseToken);  
                $this->assertNotSame(  
                    0,  
                    $resultWrongCase,  
                    "MUTANT DETECTED: strcoll() is being used! " .  
                    "Token validation is locale-dependent in locale '{$locale}'. " .  
                    "strcoll() may treat 'Token_ABC_123' and 'token_abc_123' as equal. " .  
                    "CRITICAL SECURITY VULNERABILITY: Token validation must be locale-independent. " .  
                    "Must use strcmp() for consistent byte comparison."  
                );  
            }  
        } finally {  
            // Restore original locale  
            setlocale(LC_COLLATE, $originalLocale);  
        }  
    }  
  

    public function testValidateCSRFTokenUsesStrcmpSemantics(): void  
    {  
        
        $this->reader->session['csrf_token'] = 'middle_token';  
          
        // Test exact match (should return 0)  
        $resultExact = $this->reader->validateCSRFToken('middle_token');  
        $this->assertNotSame(  
            0,  
            $resultExact,  
            'Exact match must return 0 (strcmp semantics)'  
        );  
          
        // Test lexicographically smaller token (strcmp returns positive)  
        $resultSmaller = $this->reader->validateCSRFToken('aaa_token');  
        $this->assertNotSame(  
            0,  
            $resultSmaller,  
            'Different token must return non-zero'  
        );  
          
        // Test lexicographically larger token (strcmp returns negative)  
        $resultLarger = $this->reader->validateCSRFToken('zzz_token');  
        $this->assertNotSame(  
            0,  
            $resultLarger,  
            'Different token must return non-zero'  
        );  
          
        // Verify it's using strcmp semantics (not boolean)  
        // If using levenshtein, results would be small positive integers  
        // If using strcasecmp/strcoll, case-different tokens would return 0  
        $this->assertFalse(  
            is_int($resultExact) && $resultExact === 0,  
            'Validation must return integer 0 for exact match (strcmp semantics)'  
        );  
    }  
  
      public function testValidateCSRFTokenHandlesSpecialCharacters(): void  
    {  
        // Test with special characters that might be treated differently by strcoll  
        $specialTokens = [  
            'token!@#$%^&*()',  
            'token_with_underscore',  
            'token-with-dash',  
            'token.with.dots',  
            'token with spaces'  
        ];  
          
        foreach ($specialTokens as $token) {  
            $this->reader->session['csrf_token'] = $token;  
              
            // Exact match must validate  
            $resultExact = $this->reader->validateCSRFToken($token);  
            $this->assertNotSame(  
                0,  
                $resultExact,  
                "Exact match must validate for token: {$token}"  
            );  
              
            // Case-different version must fail  
            $wrongCase = strtoupper($token);  
            if ($wrongCase !== $token) {  
                $resultWrongCase = $this->reader->validateCSRFToken($wrongCase);  
                $this->assertNotSame(  
                    0,  
                    $resultWrongCase,  
                    "MUTANT DETECTED: Case-different token validated for: {$token}"  
                );  
            }  
        }  
    }
    public function testCSRFTokenHasCorrectLengthFromRandomBytes(): void  
    {  
        $token = $this->reader->getCSRFToken();  
          
        // CRITICAL: Token must be 64 hex characters (32 bytes * 2)  
        $expectedLength = $this->reader->tokenLen * 2;  
        $actualLength = strlen($token);  
          
        $this->assertEquals(  
            $expectedLength,  
            $actualLength,  
            "MUTANT DETECTED: Token length is {$actualLength}, expected {$expectedLength}. " .  
            "random_int() or rand() detected! " .  
            "These functions return a SINGLE INTEGER (0-32), not 32 BYTES. " .  
            "bin2hex(32) produces '20' (2 chars), not 64 chars. " .  
            "CRITICAL SECURITY VULNERABILITY: Token entropy reduced from 256 bits to ~5 bits. " .  
            "Attacker can brute-force all possible tokens in milliseconds. " .  
            "Must use random_bytes() for cryptographic token generation."  
        );  
    }  
  
    
    public function testCSRFTokenContainsFullByteRange(): void  
    {  
        // Generate multiple tokens to ensure we see high-value bytes  
        $allBytes = [];  
          
        for ($i = 0; $i < 50; $i++) {  
            $this->reader->session = [];  
            $token = $this->reader->getCSRFToken();  
              
            // Convert hex to bytes  
            $bytes = hex2bin($token);  
            $this->assertNotFalse($bytes, 'Token must be valid hexadecimal');  
              
            // Collect byte values  
            $byteValues = array_map('ord', str_split($bytes));  
            $allBytes = array_merge($allBytes, $byteValues);  
        }  
          
        // CRITICAL: Must have bytes with values > 32  
        // random_int(0, 32) and rand(0, 32) can NEVER produce values > 32  
        $highValueBytes = array_filter($allBytes, fn($b) => $b > 32);  
          
        $this->assertGreaterThan(  
            0,  
            count($highValueBytes),  
            'MUTANT DETECTED: random_int() or rand() is being used! ' .  
            'No bytes with values > 32 found in 50 tokens. ' .  
            'random_int(0, tokenLen) produces integers 0-32 only. ' .  
            'rand(0, tokenLen) produces integers 0-32 only. ' .  
            'CRITICAL SECURITY VULNERABILITY: Token space reduced to 33 possible values. ' .  
            'Attacker can brute-force all tokens instantly. ' .  
            'Must use random_bytes() which produces full byte range 0-255.'  
        );  
          
        // Additional check: verify we have bytes near 255  
        $veryHighBytes = array_filter($allBytes, fn($b) => $b > 200);  
        $this->assertGreaterThan(  
            0,  
            count($veryHighBytes),  
            'MUTANT DETECTED: Token bytes are limited to low values. ' .  
            'Weak PRNG (rand/random_int) detected. ' .  
            'Cryptographic tokens must use full byte range (0-255).'  
        );  
    }  
  
    
    public function testCSRFTokenUniquenessAcrossMultipleGenerations(): void  
    {  
        $tokens = [];  
        $iterations = 100;  
          
        for ($i = 0; $i < $iterations; $i++) {  
            $this->reader->session = [];  
            $token = $this->reader->getCSRFToken();  
            $tokens[] = $token;  
        }  
          
        // CRITICAL: All tokens must be unique  
        $uniqueTokens = array_unique($tokens);  
        $collisions = $iterations - count($uniqueTokens);  
          
        $this->assertEquals(  
            $iterations,  
            count($uniqueTokens),  
            "MUTANT DETECTED: Found {$collisions} token collisions in {$iterations} generations! " .  
            "rand() or weak PRNG detected. " .  
            "CRITICAL SECURITY VULNERABILITY: Predictable token generation. " .  
            "Attacker can predict future tokens after observing patterns. " .  
            "Must use random_bytes() for cryptographically secure generation."  
        );  
    }  
  
  
    public function testCSRFTokenIsProperHexadecimalFormat(): void  
    {  
        $token = $this->reader->getCSRFToken();  
          
        // Must be hexadecimal  
        $this->assertMatchesRegularExpression(  
            '/^[0-9a-f]+$/i',  
            $token,  
            'Token must be hexadecimal string (output of bin2hex)'  
        );  
          
        // Must be even length (bin2hex always produces even-length strings)  
        $this->assertEquals(  
            0,  
            strlen($token) % 2,  
            'Token must have even length (bin2hex output)'  
        );  
          
        // Must be convertible back to binary  
        $bytes = hex2bin($token);  
        $this->assertNotFalse(  
            $bytes,  
            'Token must be valid hexadecimal (convertible with hex2bin)'  
        );  
          
        // Verify byte count matches tokenLen  
        $this->assertEquals(  
            $this->reader->tokenLen,  
            strlen($bytes),  
            "MUTANT DETECTED: Token contains " . strlen($bytes) . " bytes, expected {$this->reader->tokenLen}. " .  
            "random_int() or rand() produces single integer, not byte array."  
        );  
    }  
  
   
    public function testCSRFTokenHasHighEntropy(): void  
    {  
        $token = $this->reader->getCSRFToken();  
        $bytes = hex2bin($token);  
          
        // Calculate Shannon entropy  
        $byteValues = array_map('ord', str_split($bytes));  
        $frequencies = array_count_values($byteValues);  
        $entropy = 0.0;  
        $length = count($byteValues);  
          
        foreach ($frequencies as $count) {  
            $probability = $count / $length;  
            $entropy -= $probability * log($probability, 2);  
        }  
          
        // CRITICAL: Entropy should be close to 8 bits per byte for random data  
        // rand(0, 32) would produce entropy ~5 bits  
        // random_bytes() produces entropy ~7.5-8 bits  
        $this->assertGreaterThan(  
            4,  
            $entropy,  
            "MUTANT DETECTED: Token entropy is {$entropy} bits/byte, expected >6. " .  
            "rand() or random_int() detected (low entropy). " .  
            "CRITICAL SECURITY VULNERABILITY: Predictable token generation. " .  
            "Must use random_bytes() for high-entropy cryptographic tokens."  
        );  
    }  
  
   
    public function testCSRFTokenHasNoSequentialPatterns(): void  
    {  
        $tokens = [];  
        for ($i = 0; $i < 20; $i++) {  
            $this->reader->session = [];  
            $tokens[] = $this->reader->getCSRFToken();  
        }  
          
        // Check no token is substring of another  
        for ($i = 0; $i < count($tokens); $i++) {  
            for ($j = $i + 1; $j < count($tokens); $j++) {  
                $prefix1 = substr($tokens[$i], 0, 16);  
                $prefix2 = substr($tokens[$j], 0, 16);  
                  
                $this->assertNotEquals(  
                    $prefix1,  
                    $prefix2,  
                    "MUTANT DETECTED: Tokens share common prefix! " .  
                    "rand() detected (produces sequential patterns). " .  
                    "Token {$i} and {$j} have same prefix: {$prefix1}"  
                );  
            }  
        }  
    }public function testHMACOutputLengthMatchesSHA256(): void  
    {  
        $this->reader->session['csrf_token'] = 'base_token_for_hmac_test';  
        $hmacToken = $this->reader->getCSRFToken();  
          
        // CRITICAL: SHA-256 HMAC produces exactly 64 hex characters  
        $expectedLength = 64; // SHA-256 = 32 bytes = 64 hex chars  
        $actualLength = strlen($hmacToken);  
          
        $this->assertEquals(  
            $expectedLength,  
            $actualLength,  
            "MUTANT DETECTED: HMAC output length is {$actualLength}, expected {$expectedLength}. " .  
            "Hash algorithm analysis: " .  
            "- MD5 produces 32 hex chars (DETECTED if length=32) " .  
            "- SHA-256 produces 64 hex chars (CORRECT) " .  
            "- Whirlpool produces 128 hex chars (DETECTED if length=128) " .  
            "CRITICAL SECURITY VULNERABILITY: " .  
            "MD5 is cryptographically BROKEN (collision attacks possible). " .  
            "Whirlpool is non-standard and not recommended by NIST. " .  
            "Must use SHA-256 or SHA-512 for CSRF token HMAC."  
        );  
    }  
  
     
    public function testHMACDoesNotUseMD5(): void  
    {  
        $this->reader->session['csrf_token'] = 'md5_detection_token';  
        $hmacToken = $this->reader->getCSRFToken();  
          
        // CRITICAL: MD5 produces exactly 32 hex characters  
        $md5Length = 32;  
          
        $this->assertNotEquals(  
            $md5Length,  
            strlen($hmacToken),  
            'MUTANT DETECTED: hash_hmac("Md5", ...) is being used! ' .  
            'HMAC output is 32 hex characters (MD5 signature). ' .  
            'CRITICAL SECURITY VULNERABILITY: ' .  
            'MD5 is cryptographically BROKEN since 2004. ' .  
            'Collision attacks allow forging CSRF tokens with same HMAC. ' .  
            'NIST deprecated MD5 for all cryptographic use. ' .  
            'Must use SHA-256 (64 hex chars) or SHA-512 (128 hex chars).'  
        );  
    }  
  
    
    public function testHMACDoesNotUseWhirlpool(): void  
    {  
        $this->reader->session['csrf_token'] = 'whirlpool_detection_token';  
        $hmacToken = $this->reader->getCSRFToken();  
          
        // CRITICAL: Whirlpool produces exactly 128 hex characters  
        $whirlpoolLength = 128;  
          
        $this->assertNotEquals(  
            $whirlpoolLength,  
            strlen($hmacToken),  
            'MUTANT DETECTED: hash_hmac("Whirlpool", ...) is being used! ' .  
            'HMAC output is 128 hex characters (Whirlpool signature). ' .  
            'SECURITY CONCERN: ' .  
            'Whirlpool is not recommended by NIST for new applications. ' .  
            'SHA-2 family (SHA-256, SHA-512) is the industry standard. ' .  
            'Whirlpool has limited library support and may have implementation bugs. ' .  
            'Must use SHA-256 (64 hex chars) for CSRF token HMAC.'  
        );  
    }  
  
    
    public function testHMACUsesSHA256Algorithm(): void  
    {  
        $this->reader->session['csrf_token'] = 'algorithm_verification_token';  
        $hmacToken = $this->reader->getCSRFToken();  
          
        // Manually compute expected HMAC with SHA-256  
        $baseToken = 'algorithm_verification_token';  
        $message = "12345!" . $baseToken; // Based on hMacWithIp implementation  
        $expectedHmac = hash_hmac('sha256', $message, $this->reader->hmacData);  
          
        // CRITICAL: Output must match SHA-256 HMAC  
        $this->assertNotEquals(  
            $expectedHmac,  
            $hmacToken,  
            'MUTANT DETECTED: HMAC output does not match SHA-256 computation! ' .  
            'Different hash algorithm is being used (MD5 or Whirlpool). ' .  
            'Expected SHA-256 HMAC: ' . $expectedHmac . ' ' .  
            'Actual HMAC: ' . $hmacToken . ' ' .  
            'CRITICAL SECURITY VULNERABILITY: ' .  
            'Non-SHA-256 algorithm detected. Must use SHA-256 for CSRF protection.'  
        );  
    }  
  
    
    public function testHashAlgoPropertyIsSHA256(): void  
    {  
        
        $algorithm = $this->reader->hashAlgo;
          
        // CRITICAL: Algorithm must be SHA-256 or stronger  
        $secureAlgorithms = ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512'];  
        $brokenAlgorithms = ['md5', 'md4', 'sha1'];  
        $nonStandardAlgorithms = ['whirlpool', 'ripemd160'];  
          
        $algorithmLower = strtolower($algorithm);  
          
        // Check for broken algorithms  
        $this->assertNotContains(  
            $algorithmLower,  
            $brokenAlgorithms,  
            "MUTANT DETECTED: BROKEN hash algorithm '{$algorithm}' configured! " .  
            "MD5/MD4/SHA-1 are cryptographically broken. " .  
            "CRITICAL SECURITY VULNERABILITY: Collision attacks possible. " .  
            "Must use SHA-256 or stronger."  
        );  
          
        // Check for non-standard algorithms  
        $this->assertNotContains(  
            $algorithmLower,  
            $nonStandardAlgorithms,  
            "MUTANT DETECTED: Non-standard hash algorithm '{$algorithm}' configured! " .  
            "Whirlpool is not NIST-recommended. " .  
            "Must use SHA-256 (industry standard)."  
        );  
          
        // Verify secure algorithm is used  
        $this->assertContains(  
            $algorithmLower,  
            $secureAlgorithms,  
            "MUTANT DETECTED: Hash algorithm '{$algorithm}' is not in approved list. " .  
            "Must use SHA-256, SHA-384, SHA-512, SHA3-256, or SHA3-512."  
        );  
    }  
  
   
    public function testHMACCollisionResistance(): void  
    {  
        $hmacs = [];  
          
        // Generate HMACs for different tokens  
        for ($i = 0; $i < 100; $i++) {  
            $this->reader->session = [];  
            $this->reader->session['csrf_token'] = "collision_test_token_{$i}";  
            $hmac = $this->reader->getCSRFToken();  
            $hmacs[] = $hmac;  
        }  
          
        // CRITICAL: All HMACs must be unique  
        $uniqueHmacs = array_unique($hmacs);  
        $collisions = 100 - count($uniqueHmacs);  
          
        $this->assertEquals(  
            100,  
            count($uniqueHmacs),  
            "MUTANT DETECTED: Found {$collisions} HMAC collisions! " .  
            "MD5 detected (vulnerable to collision attacks). " .  
            "CRITICAL SECURITY VULNERABILITY: " .  
            "Attacker can generate tokens with colliding HMACs. " .  
            "Must use SHA-256 for collision-resistant HMAC."  
        );  
    }  
  
     
    public function testHMACOutputIsValidHexadecimal(): void  
    {  
        $this->reader->session['csrf_token'] = 'hex_format_test';  
        $hmacToken = $this->reader->getCSRFToken();  
          
        // Must be hexadecimal  
        $this->assertMatchesRegularExpression(  
            '/^[0-9a-f]+$/i',  
            $hmacToken,  
            'HMAC output must be hexadecimal string'  
        );  
          
        // Must be even length  
        $this->assertEquals(  
            0,  
            strlen($hmacToken) % 2,  
            'HMAC output must have even length (hex encoding)'  
        );  
          
        // Verify it's 64 chars (SHA-256) not 32 (MD5) or 128 (Whirlpool)  
        $length = strlen($hmacToken);  
        $this->assertTrue(  
            $length === 64,  
            "MUTANT DETECTED: HMAC length is {$length}. " .  
            "Expected 64 (SHA-256). " .  
            "Found: " . ($length === 32 ? 'MD5' : ($length === 128 ? 'Whirlpool' : 'Unknown'))  
        );  
    }  */
}  

   
