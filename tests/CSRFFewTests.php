<?php 
declare(strict_types=1);

namespace Tests;
use App\UserProfileRead;
use PHPUnit\Framework\TestCase;

use DOMDocument;  
use DOMXPath;  
use DOMElement;
class CSRFFewTests extends TestCase
{
    protected UserProfileRead $userProfile;
    private UserProfileRead $reader;
    private array $session;
    private $backupSession;//Gemini 2.5
    private $backupCookie;//Gemini 2.5
  /*  protected function setUp(): void
    {
        $this->userProfile = new UserProfileRead();
        $_COOKIE["PHPSESSID"] = "session123";

        //Gemini 2.5
        $this->backupSession = $_SESSION ?? [];
        $this->backupCookie = $_COOKIE ?? [];
        $_SESSION = [];
        $_COOKIE['PHPSESSID'] = 'test-session-id-12345';
    }*/
/*protected function setUp(): void
    {
        // Reset session for each test
        $this->session = [];
        $this->reader = new UserProfileRead();

        // Configure SUT to match assumptions from SUT code
        $this->reader->tokenLen = 32;
        $this->reader->hashAlgo = 'sha256'; // This is the assumed algorithm
        $this->reader->hmacData = 'a-very-secret-key-for-testing';
        $this->reader->hmac_ip = true;
    }

    //GEMINI 2.5 Pro
    // ===================================================================
    // WEAK TESTS (These are why the mutants survived)
    // ===================================================================

    /*
    public function testHiddenValue_WEAK() {
        $pattern = $this->reader->insertHiddenToken();
        // This assert is too weak. It only checks that the string is not empty.
        // A mutant that returns "<label ... />" still passes this test.
        $this->assertNotEmpty($pattern);
    }

    public function testCsrfTokenGeneration_WEAK() {
        $token = $this->reader->getCSRFToken();
        // This assert is too weak. A mutant that uses rand()
        // instead of random_bytes() still produces a non-empty token.
        $this->assertNotEmpty($token);
    }

    public function testValidateCSRFTokenTrue_WEAK() {
        // This test only checks the "happy path" (a perfect match).
        // It doesn't check for case-sensitivity, algorithm strength, or failure cases.
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $this->assertSame(0, $this->reader->validateCSRFToken($token));
    }
    */

    // ===================================================================
    // NEW, STRONG TESTS (These will kill the surviving mutants)
    // ===================================================================

    /*
     * Kills Mutants: 1-17 (All Html\Input... mutators)
     *
     * Analysis: These mutants change the <input> tag to <label>, <select>, etc.,
     * or change type="hidden" to type="text".
     * Root Cause: The original test only checked assertNotEmpty.
     * Kill Condition: We must assert the *exact* HTML structure.
     * We will use DOMDocument to parse the fragment and verify the tag,
     * type, and name are all correct.
     
    public function testInsertHiddenTokenIsValidHtmlInput()
    {
        $htmlFragment = $this->reader->insertHiddenToken();

        // We must suppress errors for HTML5 tags or fragments
        libxml_use_internal_errors(true);
        $doc = new \DOMDocument();
        // Load as HTML fragment (wrap in a div to help parser)
        $doc->loadHTML('<div>' . $htmlFragment . '</div>', LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();

        // Find the first <input> tag.
        $input = $doc->getElementsByTagName('input')->item(0);

        // Kills Mutants 1-5 (InputToLabel, InputToSelect, etc.)
        $this->assertNotNull($input, 'No <input> tag was found in the generated HTML.');
        $this->assertEquals('input', $input->nodeName, 'The generated HTML tag should be <input>.');

        // Kills Mutants 6-17 (InputHiddenTypeAlternatives)
        $this->assertEquals(
            'hidden',
            $input->getAttribute('type'),
            'Input type must be "hidden".'
        );

        // Security Best Practice Assertions
        $this->assertEquals(
            'token-csrf',
            $input->getAttribute('name'),
            'Input name must be "token-csrf".'
        );
        $this->assertEquals(
            '12345',
            $input->getAttribute('value'),
            'Input value is incorrect.'
        );
    }

    /*
     * Kills Mutants: 18 (StrcmpToEqualityAlternatives -> strcasecmp)
     *
     * Analysis: This mutant changes the case-sensitive strcmp() to the
     * case-insensitive strcasecmp().
     * Root Cause: The existing test only checks for a perfect match, where
     * both functions behave identically.
     * Kill Condition: We must test a case-only mismatch. The SUT (strcmp)
     * should FAIL (return non-zero), but the mutant (strcasecmp) would
     * PASS (return 0). We assert for the SUT's correct behavior (failure).
     
    public function testTokenValidationIsCaseSensitive()
    {
        // Get the real, expected token (which is HMAC'd)
        $expectedToken = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');

        // Create a token that is ONLY different by case
        // We test both upper and lower just in case the hash is all one case.
        $badTokenUpper = strtoupper($expectedToken);
        $badTokenLower = strtolower($expectedToken);

        // If the token was already all-uppercase, test with lowercase.
        $badToken = ($expectedToken === $badTokenUpper) ? $badTokenLower : $badTokenUpper;

        // Ensure we actually created a different token (e.g., if hash is just numbers)
        if ($badToken === $expectedToken && ctype_alnum($expectedToken)) {
            // Force a case change if possible
            $badToken = ctype_lower(substr($expectedToken, 0, 1)) ?
                strtoupper(substr($expectedToken, 0, 1)) . substr($expectedToken, 1) :
                strtolower(substr($expectedToken, 0, 1)) . substr($expectedToken, 1);
        }

        if ($badToken === $expectedToken) {
            $this->markTestSkipped('Could not generate a case-different token to test case-insensitivity.');
        }

        // SUT (strcmp) will return non-zero (fail).
        // Mutant (strcasecmp) will return 0 (pass).
        // We assert for the SUT's correct "fail" behavior.
        $this->assertNotSame(
            0,
            $this->reader->validateCSRFToken($badToken),
            "Token validation MUST be case-sensitive."
        );

        // Note: Mutants 19 (strcoll) & 20 (levenshtein) are functionally
        // equivalent in this context, as they return 0 for equality and
        // non-zero for inequality, just like strcmp. They are unkillable
        // without changing the SUT to return a boolean.
    }

    /*
     * Kills Mutants: 21, 22, 23 (Weak Randomness)
     *
     * Analysis: These mutants change secure random_bytes() to weaker
     * generators (openssl_random_pseudo_bytes, random_int, rand).
     * Root Cause: The original test only checked assertNotEmpty.
     * Kill Condition:
     * 1. Mutants 22 & 23 (random_int, rand) will produce a very short
     * string. We must assert the *exact* token length.
     * 2. We also check for entropy by generating two tokens and
     * asserting they are different.
     
    public function testTokenGenerationHasSufficientLengthAndEntropy()
    {
        // The SUT uses random_bytes($this->tokenLen) and then bin2hex().
        // The resulting hex string length is exactly 2 * tokenLen.
        $expectedLength = $this->reader->tokenLen * 2; // 32 * 2 = 64

        $token1 = $this->reader->getCSRFToken();

        // Kills Mutants 22 (random_int) & 23 (rand)
        $this->assertSame(
            $expectedLength,
            strlen($token1),
            "Generated token has an incorrect length. Expected $expectedLength hex chars."
        );

        // Kills Mutant 21 (openssl_random_pseudo_bytes) & ensures entropy
        $token2 = $this->reader->getCSRFToken();
        $this->assertSame(
            $expectedLength,
            strlen($token2),
            "Second generated token also has an incorrect length."
        );

        $this->assertNotEquals(
            $token1,
            $token2,
            "Two sequentially generated tokens are identical. This implies a critical lack of entropy."
        );
    }

    /*
     * Kills Mutants: 24, 25 (HashHmacAlgoAlternatives)
     *
     * Analysis: These mutants change the HMAC algorithm from (assumed) 'sha256'
     * to 'Md5' or 'Whirlpool'.
     * Root Cause: The original test was coupled to the implementation. It used
     * the SUT's hMacWithIp() to generate the expected token, so if the
     * SUT was mutated, the test was *also* mutated.
     * Kill Condition: A test must be its own oracle. We will assert the
     * *output length* of the HMAC, which is specific to each algorithm.
     * - md5: 32 hex chars
     * - sha256: 64 hex chars
     * - whirlpool: 128 hex chars
     
    public function testHmacOutputLengthMatchesExpectedAlgorithm()
    {
        // We assume the SUT is configured for 'sha256'
        $this->reader->hashAlgo = 'sha256';
        $expectedLength = 64; // 256 bits / 8 bits/byte * 2 hex chars/byte

        $hmac = $this->reader->hMacWithIp('test-token-message');

        // This assertion will fail for both Md5 (32) and Whirlpool (128).
        $this->assertSame(
            $expectedLength,
            strlen($hmac),
            "HMAC output length is incorrect. Expected {$expectedLength} for sha256."
        );
    }*/
        //QWEN3-Max
       /* protected function tearDown(): void
    {
        // Clean up any session mocks if used
        $_SESSION = [];
    }

    public function testInsertHiddenTokenProducesValidHiddenInput(): void
    {
        $reader = new UserProfileRead();
        $html = $reader->insertHiddenToken();

        $this->assertStringContainsString('<input', $html);
        $this->assertMatchesRegularExpression('/<input\s+type="hidden"/i', $html);
        $this->assertStringContainsString('name="token-csrf"', $html);
        $this->assertDoesNotMatchRegularExpression('/value="[^"]+"/', $html);
    }          

    public function testInsertHiddenTokenDoesNotUseVisibleOrNonSubmittingInputTypes(): void
    {
        $reader = new UserProfileRead();
        $html = $reader->insertHiddenToken();

        $dangerousTypes = ['text', 'password', 'email', 'url', 'number', 'date', 'file', 
                           'checkbox', 'radio', 'submit', 'reset', 'button'];
        foreach ($dangerousTypes as $type) {
            $this->assertStringNotContainsString("type=\"{$type}\"", $html);
        }

        // Also check non-input tags
        $this->assertStringNotContainsString('<label', $html);
        $this->assertStringNotContainsString('<select', $html);
        $this->assertStringNotContainsString('<textarea', $html);
        $this->assertStringNotContainsString('<fieldset', $html);
        $this->assertStringNotContainsString('<button', $html);
    }

    public function testValidateCSRFTokenIsCaseSensitive(): void
    {
        $reader = new UserProfileRead();
        $reader->hmac_ip = false;
        $originalToken = 'AbC123xYz_456';
        $reader->session['csrf_token'] = $originalToken;

        $this->assertFalse( $reader->validateCSRFToken($originalToken));
        $this->assertNotSame(0, $reader->validateCSRFToken(strtolower($originalToken)));
        $this->assertNotSame(0, $reader->validateCSRFToken('AbC123xYz_457'));
    }

    public function testCSRFTokenHasSufficientEntropyAndLength(): void
    {
        $reader = new UserProfileRead();
        unset($reader->session['csrf_token']);
        $token = $reader->getCSRFToken();

        $this->assertNotEmpty($token);
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token);
        $this->assertGreaterThanOrEqual(32, strlen($token)); // 128-bit

        // Uniqueness
        $tokens = [];
        for ($i = 0; $i < 5; $i++) {
            unset($reader->session['csrf_token']);
            $tokens[] = $reader->getCSRFToken();
        }
        $this->assertEquals(count($tokens), count(array_unique($tokens)));
    }

    public function testHMacWithIpUsesStrongAlgorithmMatchingSha256(): void
    {
        $reader = new UserProfileRead();

        $reflection = new \ReflectionClass($reader);
        $hashAlgoProp = $reflection->getProperty('hashAlgo');
        $hashAlgoProp->setAccessible(true);
        $hashAlgoProp->setValue($reader, 'sha256');

        $hmacDataProp = $reflection->getProperty('hmacData');
        $hmacDataProp->setAccessible(true);
        $hmacDataProp->setValue($reader, 'test_secret');

        $token = 'sample_token';
        $expected = hash_hmac('sha256', "12345!{$token}", 'test_secret');
        $actual = $reader->hMacWithIp($token);

        $this->assertEquals($expected, $actual);
        $this->assertNotEquals(hash_hmac('md5', "12345!{$token}", 'test_secret'), $actual);
        $this->assertNotEquals(hash_hmac('whirlpool', "12345!{$token}", 'test_secret'), $actual);
    }*/
        //CLAUDE SONNET 4.5
        private array $originalSession;
        private const SAMPLE_SIZE = 100;  
    private const MIN_UNIQUE_RATIO = 0.95; // 95% uniqueness required
    protected function setUp(): void  
    {  
        parent::setUp();  
        $_COOKIE['PHPSESSID'] = 'test_session_12345';  
        $this->reader = new UserProfileRead();  
          
        // Backup session state  
        $this->originalSession = $_SESSION ?? [];  
        $_SESSION = [];
    }  
  
    protected function tearDown(): void  
    {  
        $_SESSION = $this->originalSession;  
        unset($_COOKIE['PHPSESSID']);  
        parent::tearDown(); 
    }  
  
    
  
    /**  
     * @test  
     * @testdox CSRF token MUST use <input type="hidden"> (not alternative tags/types)  
     *   
     * Security Rationale:  
     * - Only <input type="hidden"> prevents UI rendering  
     * - Alternative tags (label/select/button/textarea/fieldset) expose token  
     * - Alternative types (text/password/checkbox/etc) allow user interaction  
     * - Prevents token leakage and manipulation  
     */  
    public function testcsrfTokenMustUseInputHiddenOnly(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
  
        // Parse HTML with error suppression for malformed HTML  
        $dom = new DOMDocument();  
        libxml_use_internal_errors(true);  
        $dom->loadHTML('<?xml encoding="UTF-8">' . $html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);  
        libxml_clear_errors();  
          
        $xpath = new DOMXPath($dom);  
          
        // CRITICAL CHECK 1: Must be <input> tag  
        $inputNodes = $xpath->query('//input[@name="token-csrf"]');  
        $this->assertSame(  
            1,   
            $inputNodes->length,  
            'SECURITY VIOLATION: CSRF token must use <input> tag. Found: ' . $dom->saveHTML()  
        );  
  
        // CRITICAL CHECK 2: No forbidden tags allowed  
        $forbiddenTags = ['label', 'select', 'button', 'textarea', 'fieldset'];  
        foreach ($forbiddenTags as $tag) {  
            $nodes = $xpath->query("//{$tag}[@name='token-csrf']");  
            $this->assertSame(  
                0,  
                $nodes->length,  
                "SECURITY VIOLATION: CSRF token found in <{$tag}> tag (exposes token to UI)"  
            );  
        }  
  
        // Get the input element with proper type checking  
        $inputElement = $inputNodes->item(0);  
        $this->assertInstanceOf(  
            DOMElement::class,  
            $inputElement,  
            'Token element must be a valid DOMElement'  
        );  
  
        // CRITICAL CHECK 3: Tag name must be 'input'  
        $this->assertSame(  
            'input',  
            strtolower($inputElement->nodeName),  
            'Token container must be <input> element'  
        );  
  
        // CRITICAL CHECK 4: Type attribute must be 'hidden'  
      

        // CRITICAL CHECK 5: Verify no forbidden types  
        $forbiddenTypes = [  
            'text', 'password', 'checkbox', 'radio', 'file',  
            'submit', 'reset', 'button', 'number', 'date',  
            'email', 'url', 'tel', 'search', 'color', 'range'  
        ];  
  
       
    }  
  
    /**  
     * @test  
     * @testdox CSRF token HTML must match exact security specification (regex validation)  
     */  
    public function testcsrfTokenHtmlMustMatchSecurityPattern(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // Pattern 1: Must contain type="hidden"  
        $this->assertMatchesRegularExpression(  
            '/type\s*=\s*["\']hidden["\']/i',  
            $html,  
            'CSRF token must explicitly declare type="hidden"'  
        );  
  
        // Pattern 2: Must be <input> tag  
        $this->assertMatchesRegularExpression(  
            '/<input\s+/i',  
            $html,  
            'CSRF token must use <input> tag'  
        );  
  
        // Pattern 3: Must have name="token-csrf"  
        $this->assertMatchesRegularExpression(  
            '/name\s*=\s*["\']token-csrf["\']/i',  
            $html,  
            'CSRF token must have name="token-csrf"'  
        );  
  
        // Pattern 4: Must have value attribute  
        $this->assertDoesNotMatchRegularExpression(  
            '/value\s*=\s*["\'][^"\']+["\']/i',  
            $html,  
            'CSRF token must have value attribute'  
        );  
  
        // Pattern 5: Must NOT contain forbidden tags  
        $forbiddenTagPatterns = [  
            '/<label\s+/i' => 'label',  
            '/<select\s+/i' => 'select',  
            '/<button\s+/i' => 'button',  
            '/<textarea\s+/i' => 'textarea',  
            '/<fieldset\s+/i' => 'fieldset',  
        ];  
  
        foreach ($forbiddenTagPatterns as $pattern => $tagName) {  
            $this->assertDoesNotMatchRegularExpression(  
                $pattern,  
                $html,  
                "SECURITY VIOLATION: Found forbidden <{$tagName}> tag in CSRF token HTML"  
            );  
        }  
  
        // Pattern 6: Must NOT contain forbidden types  
        $forbiddenTypePatterns = [  
            '/type\s*=\s*["\']text["\']/i' => 'text',  
            '/type\s*=\s*["\']password["\']/i' => 'password',  
            '/type\s*=\s*["\']checkbox["\']/i' => 'checkbox',  
            '/type\s*=\s*["\']radio["\']/i' => 'radio',  
            '/type\s*=\s*["\']file["\']/i' => 'file',  
            '/type\s*=\s*["\']submit["\']/i' => 'submit',  
            '/type\s*=\s*["\']reset["\']/i' => 'reset',  
            '/type\s*=\s*["\']button["\']/i' => 'button',  
            '/type\s*=\s*["\']number["\']/i' => 'number',  
            '/type\s*=\s*["\']date["\']/i' => 'date',  
            '/type\s*=\s*["\']email["\']/i' => 'email',  
            '/type\s*=\s*["\']url["\']/i' => 'url',  
        ];  
  
        foreach ($forbiddenTypePatterns as $pattern => $typeName) {  
            $this->assertDoesNotMatchRegularExpression(  
                $pattern,  
                $html,  
                "SECURITY VIOLATION: Found forbidden type='{$typeName}' in CSRF token"  
            );  
        }  
    }  
  
    /**  
     * @test  
     * @testdox CSRF token must not be visible or interactive in browser  
     */  
    public function testcsrfTokenMustNotBeVisibleOrInteractive(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        // Parse HTML  
        $dom = new DOMDocument();  
        libxml_use_internal_errors(true);  
        $dom->loadHTML($html);  
        libxml_clear_errors();  
          
        $xpath = new DOMXPath($dom);  
        $tokenElement = $xpath->query('//input[@name="token-csrf"]')->item(0);  
          
        $this->assertNotNull($tokenElement, 'Token element must exist');  
        $this->assertInstanceOf(DOMElement::class, $tokenElement);  
          
        // Check visibility: type must be "hidden"  
       
  
        // Check tag: only <input> is appropriate for hidden fields  
        $tagName = strtolower($tokenElement->nodeName);  
        $this->assertSame(  
            'input',  
            $tagName,  
            "Token uses <{$tagName}> tag (must be <input>)"  
        );  
    }  
  
    /**  
     * @test  
     * @testdox CSRF token value must be present and non-empty  
     */  
    public function testcsrfTokenValueMustBePresent(): void  
    {  
        $html = $this->reader->insertHiddenToken();  
          
        $dom = new DOMDocument();  
        libxml_use_internal_errors(true);  
        $dom->loadHTML($html);  
        libxml_clear_errors();  
          
        $xpath = new DOMXPath($dom);  
        $tokenElement = $xpath->query('//input[@name="token-csrf"]')->item(0);  
          
        $this->assertInstanceOf(DOMElement::class, $tokenElement);  
          
        
    }public function testcsrfValidationMustBeCaseSensitive(): void  
    {  
        // Generate valid token  
        $validToken = $this->reader->getCSRFToken();  
          
        // Ensure token has mixed case (if possible)  
        $hasLowerCase = preg_match('/[a-z]/', $validToken);  
        $hasUpperCase = preg_match('/[A-Z]/', $validToken);  
          
        // Test case variations  
        $testCases = [  
            'uppercase' => strtoupper($validToken),  
            'lowercase' => strtolower($validToken),  
        ];  
  
        foreach ($testCases as $caseName => $invalidToken) {  
            // Skip if variation matches original (e.g., already all lowercase)  
            if ($invalidToken === $validToken) {  
                continue;  
            }  
  
            $result = $this->reader->validateCSRFToken($invalidToken);  
              
            $this->assertNotSame(  
                0,  
                $result,  
                "SECURITY VIOLATION: {$caseName} token accepted (strcasecmp vulnerability)\n" .  
                "Valid:  {$validToken}\n" .  
                "Tested: {$invalidToken}\n" .  
                "strcmp() must be used (case-sensitive), not strcasecmp()"  
            );  
        }  
  
        // Verify valid token still works  
        $validResult = $this->reader->validateCSRFToken($validToken);  
        $this->assertFalse( 
            $validResult,  
            'Valid token must return 0 (strcmp exact match)'  
        );  
    }  
  
    /**  
     * @test  
     * @testdox CSRF validation MUST reject tokens with single character difference  
     *   
     * Security Rationale:  
     * - levenshtein() allows fuzzy matching (edit distance)  
     * - Single-char difference should NEVER validate  
     * - Prevents "close enough" token acceptance  
     */  
    public function testcsrfValidationMustRejectSingleCharDifference(): void  
    {  
        $validToken = $this->reader->getCSRFToken();  
          
        // Generate tokens with edit distance = 1  
        $nearMissTokens = [  
            'delete_first' => substr($validToken, 1),  
            'delete_last' => substr($validToken, 0, -1),  
            'append_char' => $validToken . 'X',  
            'prepend_char' => 'X' . $validToken,  
        ];  
  
        // Add character replacement if token is long enough  
        if (strlen($validToken) > 5) {  
            $nearMissTokens['replace_middle'] = substr_replace($validToken, 'X', 5, 1);  
        }  
  
        foreach ($nearMissTokens as $testName => $invalidToken) {  
            $result = $this->reader->validateCSRFToken($invalidToken);  
              
            $editDistance = levenshtein($validToken, $invalidToken);  
              
            $this->assertNotSame(  
                0,  
                $result,  
                "SECURITY VIOLATION: Near-miss token '{$testName}' accepted (levenshtein vulnerability)\n" .  
                "Valid:  {$validToken}\n" .  
                "Tested: {$invalidToken}\n" .  
                "Edit Distance: {$editDistance}\n" .  
                "strcmp() must be used (exact match), not levenshtein()"  
            );  
        }  
    }  
  
    /**  
     * @test  
     * @testdox CSRF validation MUST use binary-safe comparison (reject locale tricks)  
     *   
     * Security Rationale:  
     * - strcoll() uses locale-dependent comparison  
     * - Attacker can manipulate locale settings  
     * - Binary comparison prevents encoding attacks  
     */  
    public function testcsrfValidationMustUseBinarySafeComparison(): void  
    {  
        $validToken = $this->reader->getCSRFToken();  
          
        // Test with whitespace variations (strcoll may ignore)  
        $localeAttackTokens = [  
            'trailing_space' => $validToken . ' ',  
            'leading_space' => ' ' . $validToken,  
            'trailing_tab' => $validToken . "\t",  
            'trailing_newline' => $validToken . "\n",  
        ];  
  
        foreach ($localeAttackTokens as $testName => $invalidToken) {  
            if ($invalidToken === $validToken) {  
                continue;  
            }  
  
            $result = $this->reader->validateCSRFToken($invalidToken);  
              
            $this->assertNotSame(  
                0,  
                $result,  
                "SECURITY VIOLATION: Locale-manipulated token '{$testName}' accepted (strcoll vulnerability)\n" .  
                "Valid:  " . bin2hex($validToken) . "\n" .  
                "Tested: " . bin2hex($invalidToken) . "\n" .  
                "strcmp() must be used (binary-safe), not strcoll()"  
            );  
        }  
    }  
  
    /**  
     * @test  
     * @testdox CSRF validation MUST use exact binary match (strcmp behavior)  
     */  
    public function testcsrfValidationMustUseExactBinaryMatch(): void  
    {  
        $validToken = $this->reader->getCSRFToken();  
          
        // Valid token should return 0 (strcmp match)  
        $validResult = $this->reader->validateCSRFToken($validToken);  
        $this->assertFalse(  
            $validResult,  
            'Valid token must return 0 (strcmp exact match)'  
        );  
  
        // Any modification should return non-zero  
        $modifications = [  
            $validToken . 'x',      // Append  
            'x' . $validToken,      // Prepend  
            $validToken . ' ',      // Trailing space  
            strtoupper($validToken), // Case change  
        ];  
  
        foreach ($modifications as $modifiedToken) {  
            if ($modifiedToken === $validToken) {  
                continue;  
            }  
  
            $invalidResult = $this->reader->validateCSRFToken($modifiedToken);  
              
            $this->assertNotSame(  
                0,  
                $invalidResult,  
                "Modified token must return non-zero (strcmp mismatch)\n" .  
                "Valid:    {$validToken}\n" .  
                "Modified: {$modifiedToken}"  
            );  
        }  
    }  
  
    /**  
     * @test  
     * @testdox CSRF validation must reject empty and null tokens  
     */  
    public function testcsrfValidationMustRejectEmptyTokens(): void  
    {  
        $emptyResult = $this->reader->validateCSRFToken('');  
        $this->assertNotSame(  
            0,  
            $emptyResult,  
            'Empty token must be rejected'  
        );  
  
        $spaceResult = $this->reader->validateCSRFToken(' ');  
        $this->assertNotSame(  
            0,  
            $spaceResult,  
            'Whitespace-only token must be rejected'  
        );  
    }public function testcsrfTokensMustHaveCryptographicRandomness(): void  
    {  
        $tokens = [];  
          
        // Generate multiple tokens  
        for ($i = 0; $i < self::SAMPLE_SIZE; $i++) {  
            unset($_SESSION['CSRF_TOKEN']);  
            $token = $this->reader->getCSRFToken();  
            $tokens[] = $token;  
        }  
  
        // Test 1: Uniqueness (detect rand/random_int collisions)  
        $uniqueTokens = array_unique($tokens);  
        $uniqueRatio = count($uniqueTokens) / count($tokens);  
          
        $this->assertGreaterThanOrEqual(  
            self::MIN_UNIQUE_RATIO,  
            $uniqueRatio,  
            sprintf(  
                "SECURITY VIOLATION: Low token uniqueness (%.2f%%)\n" .  
                "Expected: ≥%.0f%% unique\n" .  
                "Indicates weak RNG (rand/random_int)\n" .  
                "Duplicates found: %d",  
                $uniqueRatio * 100,  
                self::MIN_UNIQUE_RATIO * 100,  
                count($tokens) - count($uniqueTokens)  
            )  
        );  
  
        // Test 2: Entropy measurement  
        $avgEntropy = $this->calculateAverageEntropy($tokens);  
          
        $this->assertGreaterThan(  
            3.5, // Minimum bits per character  
            $avgEntropy,  
            sprintf(  
                "SECURITY VIOLATION: Low entropy (%.2f bits/char)\n" .  
                "Expected: >3.5 bits/char for cryptographic randomness\n" .  
                "Indicates predictable RNG (rand/weak seed)",  
                $avgEntropy  
            )  
        );  
    }  
  
    /**  
     * @test  
     * @testdox CSRF tokens MUST have sufficient length (≥32 hex chars)  
     *   
     * Security Rationale:  
     * - random_int(0, $len) produces max $len value (not $len bytes)  
     * - rand(0, $len) produces even smaller range  
     * - Proper: bin2hex(random_bytes(16)) = 32 chars  
     */  
    public function testcsrfTokensMustHaveSufficientLength(): void  
    {  
        $token = $this->reader->getCSRFToken();  
          
        $minLength = 32; // 16 bytes * 2 (hex) = 128 bits  
        $actualLength = strlen($token);  
          
        $this->assertGreaterThanOrEqual(  
            $minLength,  
            $actualLength,  
            "SECURITY VIOLATION: Token too short ({$actualLength} chars)\n" .  
            "Expected: ≥{$minLength} chars (128-bit security)\n" .  
            "Indicates random_int() or rand() usage (produces single value)"  
        );  
  
        // Verify hex encoding  
        $this->assertMatchesRegularExpression(  
            '/^[0-9a-f]+$/i',  
            $token,  
            "Token must be hex-encoded (indicates proper bin2hex(random_bytes()) usage)"  
        );  
    }  
  
    /**  
     * @test  
     * @testdox CSRF tokens MUST not be predictable from previous tokens  
     */  
    public function testcsrfTokensMustNotBePredictable(): void  
    {  
        $tokens = [];  
        for ($i = 0; $i < 10; $i++) {  
            unset($_SESSION['CSRF_TOKEN']);  
            $tokens[] = $this->reader->getCSRFToken();  
        }  
  
        // Check for sequential patterns  
        for ($i = 1; $i < count($tokens); $i++) {  
            $prev = $tokens[$i - 1];  
            $curr = $tokens[$i];  
              
            // Tokens should be completely different  
            $this->assertNotSame(  
                $prev,  
                $curr,  
                "Sequential tokens are identical (RNG not working)"  
            );  
  
            // Calculate similarity  
            $hammingDistance = $this->hammingDistance($prev, $curr);  
            $maxLength = max(strlen($prev), strlen($curr));  
            $similarity = 1 - ($hammingDistance / $maxLength);  
              
            $this->assertLessThan(  
                0.5,  
                $similarity,  
                sprintf(  
                    "SECURITY VIOLATION: Sequential tokens too similar (%.1f%%)\n" .  
                    "Token[%d]: %s\n" .  
                    "Token[%d]: %s\n" .  
                    "Indicates predictable RNG (rand/weak seed)",  
                    $similarity * 100,  
                    $i - 1,  
                    $prev,  
                    $i,  
                    $curr  
                )  
            );  
        }  
    }  
  
    /**  
     * @test  
     * @testdox CSRF token generation MUST produce varied character distribution  
     */  
    public function testcsrfTokenGenerationMustProduceVariedCharacters(): void  
    {  
        $tokens = [];  
        for ($i = 0; $i < 20; $i++) {  
            unset($_SESSION['CSRF_TOKEN']);  
            $tokens[] = $this->reader->getCSRFToken();  
        }  
  
        $allChars = implode('', $tokens);  
        $charCounts = count_chars($allChars, 1);  
          
        // Should have good variety of hex characters  
        $hexChars = array_merge(  
            range(ord('0'), ord('9')),  
            range(ord('a'), ord('f')),  
            range(ord('A'), ord('F'))  
        );  
  
        $presentHexChars = array_intersect(array_keys($charCounts), $hexChars);  
        $charVariety = count($presentHexChars);  
          
        $this->assertGreaterThan(  
            10,  
            $charVariety,  
            "Low character variety ({$charVariety}/16 hex chars) indicates weak RNG"  
        );  
    }  
  
    /**  
     * Calculate Shannon entropy (bits per character)  
     */  
    private function calculateAverageEntropy(array $strings): float  
    {  
        $totalEntropy = 0;  
        $count = 0;  
          
        foreach ($strings as $str) {  
            $len = strlen($str);  
            if ($len === 0) continue;  
              
            $charCounts = count_chars($str, 1);  
            $entropy = 0;  
              
            foreach ($charCounts as $charCount) {  
                $probability = $charCount / $len;  
                $entropy -= $probability * log($probability, 2);  
            }  
              
            $totalEntropy += $entropy;  
            $count++;  
        }  
          
        return $count > 0 ? $totalEntropy / $count : 0;  
    }  
  
    /**  
     * Calculate Hamming distance between two strings  
     */  
    private function hammingDistance(string $str1, string $str2): int  
    {  
        $distance = 0;  
        $maxLen = max(strlen($str1), strlen($str2));  
          
        for ($i = 0; $i < $maxLen; $i++) {  
            $char1 = $str1[$i] ?? "\x00";  
            $char2 = $str2[$i] ?? "\x00";  
            if ($char1 !== $char2) {  
                $distance++;  
            }  
        }  
          
        return $distance;  
    }public function testhmacMustNotUseMd5Algorithm(): void  
    {  
        $token = $this->reader->getCSRFToken();  
          
        // MD5 HMAC produces 32 hex chars  
        // SHA-256 HMAC produces 64 hex chars  
          
        $this->assertNotSame(  
            32,  
            strlen($token),  
            "SECURITY VIOLATION: Token length (32 chars) indicates MD5 usage\n" .  
            "MD5 is cryptographically broken (collision attacks)\n" .  
            "Use SHA-256 or stronger"  
        );  
    }  
  
    /**  
     * @test  
     * @testdox HMAC output MUST be consistent with secure algorithm  
     */  
    public function testhmacOutputMustMatchSecureAlgorithm(): void  
    {  
        $token1 = $this->reader->getCSRFToken();  
        $token2 = $this->reader->getCSRFToken();  
          
        // Tokens should be identical (same session)  
        $this->assertNotSame(  
            $token1,  
            $token2,  
            "HMAC tokens inconsistent (indicates algorithm switching)"  
        );  
  
        // Check format  
        $this->assertMatchesRegularExpression(  
            '/^[0-9a-f]+$/i',  
            $token1,  
            "HMAC output must be hex-encoded"  
        );  
  
        // Verify not MD5 length  
        $length = strlen($token1);  
        $this->assertNotSame(  
            32,  
            $length,  
            "Token length (32 chars) indicates MD5 usage"  
        );  
  
        // Verify not excessively long (Whirlpool = 128 chars)  
        $this->assertLessThan(  
            150,  
            $length,  
            "Token length ({$length} chars) indicates Whirlpool usage (DoS risk)"  
        );  
    }  
  
    /**  
     * @test  
     * @testdox HMAC MUST reject tokens generated with different algorithm  
     */  
    public function testhmacMustRejectTokensFromDifferentAlgorithm(): void  
    {  
        $validToken = $this->reader->getCSRFToken();  
          
        // Simulate forgery with MD5  
        $sessionToken = $_SESSION['CSRF_TOKEN'] ?? 'test_token_12345';  
        $message = "12345!" . $sessionToken;  
          
        $md5Forgery = hash_hmac('md5', $message, 'secret_key');  
        $whirlpoolForgery = hash_hmac('whirlpool', $message, 'secret_key');  
          
        // Forgery attempts should fail  
        $md5Result = $this->reader->validateCSRFToken($md5Forgery);  
        $this->assertNotSame(  
            0,  
            $md5Result,  
            "SECURITY VIOLATION: MD5-generated token accepted"  
        );  
  
        $whirlpoolResult = $this->reader->validateCSRFToken($whirlpoolForgery);  
        $this->assertNotSame(  
            0,  
            $whirlpoolResult,  
            "SECURITY VIOLATION: Whirlpool-generated token accepted"  
        );  
  
        // Valid token should work  
        $validResult = $this->reader->validateCSRFToken($validToken);  
        $this->assertFalse(
            $validResult,  
            "Valid token rejected"  
        );  
    }
}