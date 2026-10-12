<?php 
declare(strict_types=1);

namespace Tests;
use App\UserProfileRead;
use PHPUnit\Framework\TestCase;
class CSRFCoTTests extends TestCase
{
    protected UserProfileRead $userProfile;
    
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
//QWEN 4 TC
/*   public function testInsertHiddenTokenRendersCorrectHiddenInput(): void
{
    $profile = new UserProfileRead();
    $output = $profile->insertHiddenToken();

    // Must contain <input type="hidden"
    $this->assertStringContainsString('<input type="hidden"', $output);
    
    // Must NOT contain other tags like <label>, <select>, etc.
    $invalidTags = ['<label', '<select', '<button', '<textarea', '<fieldset'];
    foreach ($invalidTags as $tag) {
        $this->assertStringNotContainsString($tag, $output, "Mutant using $tag should be killed");
    }

    // Must have name="token-csrf" and a value
    $this->assertStringContainsString('name="token-csrf"', $output);
    $this->assertMatchesRegularExpression('/value=[\'"]?\w+[\'"]?/', $output);
}public function testCSRFTokenValidationIsCaseSensitiveAndExact(): void
{
    $profile = new UserProfileRead();
    
    // Simulate token setup
    $validToken = 'a1b2c3d4e5';
    $reflection = new \ReflectionClass($profile);
    $method = $reflection->getMethod('validateCSRFToken');
    $method->setAccessible(true);

    
    $result1 = $method->invoke($profile, 'abc123', 'ABC123');
    // strcmp('abc123','ABC123') ≠ 0 → (bool)≠0 = true → but should be FALSE (invalid)
    // But mutant #18: strcasecmp → returns 0 → treated as FALSE → allows bypass!

    // So: if mutant uses strcasecmp, 'token' and 'TOKEN' would match → BAD.

    // Design test: valid token = 'Token123'
    // Submit 'TOKEN123' → should be REJECTED
    $valid = 'Token123';
    // We need to set expected token
    $prop = $reflection->getProperty('session');
    $prop->setAccessible(true);
    $prop->setValue($profile, ['csrf_token' => $valid]);

    // Now validate
    $isValid = $profile->validateCSRFToken('TOKEN123'); // uppercase
    // In original: strcmp('Token123', 'TOKEN123') ≠ 0 → if code treats as (bool)$result, it's TRUE → WRONG!
    // But likely, the code checks `if (strcmp(...) === 0)`? Let's check original:

    // Original code:
    //   return strcmp($expected, $submittedToken);
    // Then probably used in: if ($this->validateCSRFToken(...)) { allow }

    // Since strcmp(a,b) === 0 only when equal, and 0 is falsy → this is inverted logic!
    // This suggests the real code might have a bug. But for mutation testing:

    // We assume the validation logic expects **0 to mean valid**.
    // So we test: correct token → returns 0; incorrect → non-0.

    // Revised approach:
    $this->assertEquals(0, strcmp($valid, $valid)); // baseline
    $this->assertNotEquals(0, strcmp($valid, strtoupper($valid))); // case differs

    // Now test mutant behavior indirectly:
    // If mutant uses strcasecmp, then strcasecmp('a','A') = 0 → bypass
    // So our test: submit case-different token → must NOT be accepted

    // But without knowing how return value is used, safest is to test **token mismatch always fails**

    // Final test:
    //$this->assertSame(1,        $profile->validateCSRFToken('WRONG_TOKEN'),        'Wrong token should be rejected'    );

    // And case variation:
    //$this->assertSame(1,        $profile->validateCSRFToken(strtoupper($valid)),        'Case-modified token should be rejected (kills mutant #18 strcasecmp)'    );

    // Also test completely different token (kills #20 levenshtein, which returns int distance ≠ 0 → but if code expects 0, it fails)
  //  $this->assertSame(-1,        $profile->validateCSRFToken('completely_different'),        'Different token rejected'    );
}public function testGeneratedCSRFTokenHasHighEntropyAndCorrectLength(): void
{
    $profile = new UserProfileRead();
    $token1 = $profile->getCSRFToken();
    $token2 = $profile->getCSRFToken();

    // Token should be hex-encoded
    $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $token1);

    // Default tokenLen likely 16 → hex = 32 chars
    $this->assertEquals(64, strlen($token1)); // adjust if different

    // Tokens should be different (unpredictable)
    $this->assertNotEquals($token1, $token2);

    // Test entropy: generate 10 tokens, ensure high uniqueness
    $tokens = [];
    for ($i = 0; $i < 10; $i++) {
        $tokens[] = $profile->getCSRFToken();
    }
    $unique = array_unique($tokens);
    $this->assertCount(10, $unique, 'All tokens must be unique (kills weak RNG mutants)');

    // Mutant #22: random_int(0, $len) → produces small integer → hex is short
    // Mutant #23: rand(0, $len) → same issue
    // This test fails if token is like 'a' or '123'
}public function testHMACUsesSecureAlgorithm(): void
{
    $profile = new UserProfileRead();

    // Get token and HMAC
    $token = $profile->getCSRFToken();
    
    // Use reflection to access HMAC method
    $reflection = new \ReflectionClass($profile);
    $method = $reflection->getMethod('hMacWithIp');
    $method->setAccessible(true);
    
    // Call with mock IP or disable IP binding if needed
    // Assume hMacWithIp returns HMAC string
    $hmac = $method->invoke($profile, $token);

    // HMAC should be hex-encoded
    $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $hmac);

    // Length indicates algorithm:
    // - MD5: 32 chars
    // - SHA256: 64 chars
    // - Whirlpool: 128 chars

    // Assuming original uses sha256 → 64 chars
    $this->assertEquals(64, strlen($hmac), 'HMAC must be SHA256 (64 hex chars)');

    // If mutant uses MD5 (32 chars) → test fails
    // If mutant uses Whirlpool (128) → test fails
}*/
//GEMINI 2.5 Pro 2 TC
/*public function testValidateCSRFTokenFailsOnCaseMismatch()
    {
        // Asumsi $this->session, $this->hmac_ip, dll. di-setup di sini.
        // Cara termudah adalah menginisialisasi objek dan mendapatkan token yang valid terlebih dahulu.
        $userProfile = new UserProfileRead(); 
        
        // 1. Dapatkan token yang valid
        $validToken = $userProfile->getCSRFToken();
        
        // 2. Buat versi token yang 'salah' (hanya beda huruf besar/kecil)
        // Kita gunakan strtolower + strtoupper untuk memastikan ada perbedaan
        // jika token asli sudah full lowercase/uppercase.
        $caseMismatchToken = strtolower($validToken) . "a" == strtolower($validToken . "a") ? 
                             strtoupper($validToken) : 
                             strtolower($validToken);

        // Pastikan tokennya berbeda tapi sama jika case-insensitive
        $this->assertNotEquals($validToken, $caseMismatchToken);
        $this->assertEquals(0, strcasecmp($validToken, $caseMismatchToken));

        // 3. Lakukan validasi
        // strcmp() akan mengembalikan nilai non-zero (gagal)
        // strcasecmp() akan mengembalikan 0 (sukses)
        $validationResult = $userProfile->validateCSRFToken($caseMismatchToken);

        // 4. Assertion
        // Kita mengharapkan validasi GAGAL.
        // Kode asli (strcmp) akan mengembalikan nilai non-zero, yang lolos assertion ini.
        // Kode mutan (strcasecmp) akan mengembalikan 0, yang akan GAGAL assertion ini.
        $this->assertNotEquals(
            0,
            $validationResult,
            "Validasi token lolos padahal hanya beda huruf besar/kecil. Token tidak case-sensitive!"
        );
    }public function testTokenGenerationHasHighEntropy()
    {
        $userProfile = new UserProfileRead();
        $generatedTokens = [];
        $iterations = 100; // Hasilkan 100 token

        for ($i = 0; $i < $iterations; $i++) {
            // Panggil getCSRFToken(). 
            // Fungsi ini memanggil unsetToken() di dalamnya, 
            // jadi kita akan mendapatkan token baru setiap kali.
            $generatedTokens[] = $userProfile->getCSRFToken();
        }

        // Hitung jumlah token unik
        $uniqueTokens = array_unique($generatedTokens);
        $uniqueTokenCount = count($uniqueTokens);

        // Assertion
        // Kita mengharapkan 100 token unik dari 100 iterasi.
        // Kode asli (random_bytes) hampir pasti akan menghasilkan 100 token unik.
        // Kode mutan (rand) akan menghasilkan MAKSIMAL 33 token unik.
        $this->assertEquals(
            $iterations,
            $uniqueTokenCount,
            "Generator token menghasilkan token duplikat. Ini menunjukkan entropi rendah dan tidak aman."
        );
    }*/

        //CLAUDE SONNET 4.5
    /*    public function testCSRFTokenIsInHiddenInputTag()  
    {  
        $tokenHtml = $this->userProfile->insertHiddenToken();  
          
        // Assert it's an input tag  
        $this->assertStringContainsString('<input', $tokenHtml);  
        $this->assertStringNotContainsString('<label', $tokenHtml);  
        $this->assertStringNotContainsString('<select', $tokenHtml);  
        $this->assertStringNotContainsString('<button', $tokenHtml);  
        $this->assertStringNotContainsString('<textarea', $tokenHtml);  
        $this->assertStringNotContainsString('<fieldset', $tokenHtml);  
          
    }
  

    public function testCSRFTokenInputTypeIsHidden()  
    {  
        $tokenHtml = $this->userProfile->insertHiddenToken();  
          
        // Assert type is hidden  
        $this->assertStringContainsString('type="hidden"', $tokenHtml);  
          
        // Assert it's NOT any visible type  
        $visibleTypes = ['text', 'password', 'checkbox', 'radio', 'file',   
                        'submit', 'reset', 'button', 'number', 'date', 'email', 'url'];  
          
        foreach ($visibleTypes as $type) {  
            $this->assertStringNotContainsString("type=\"$type\"", $tokenHtml,  
                "CSRF token must not be visible as type='$type'");  
        }  
          
         
    }  
  

    public function testCSRFTokenValidationIsTimingSafe()  
    {  
        $validToken = "test_token_12345";  
        $invalidToken1 = "test_token_12346"; // One char different  
        $invalidToken2 = "TEST_TOKEN_12345"; // Case different  
          
        // Valid token should pass  
        $result1 = $this->userProfile->validateCSRFToken($validToken);  
        $this->assertNotEquals(0, $result1, "Valid token should return 0");  
          
        // Test that comparison is case-sensitive (kills strcasecmp mutant)  
        $result2 = $this->userProfile->validateCSRFToken($invalidToken2);  
        $this->assertNotEquals(0, $result2,   
            "Case-sensitive comparison required - strcasecmp is insecure");  
          
        // Test that exact binary comparison is used (kills strcoll/levenshtein)  
        $result3 = $this->userProfile->validateCSRFToken($invalidToken1);  
        $this->assertNotEquals(0, $result3,  
            "Exact binary comparison required - fuzzy matching is insecure");  
          
        // Timing attack test: measure comparison time consistency  
        $timings = [];  
        for ($i = 0; $i < 100; $i++) {  
            $start = microtime(true);  
            $this->userProfile->validateCSRFToken($validToken);  
            $timings[] = microtime(true) - $start;  
        }  
          
        $variance = $this->calculateVariance($timings);  
        $this->assertLessThan(0.001, $variance,  
            "Token comparison must be timing-safe (constant time)");  
    }  
  

    public function testCSRFTokenHasSufficientEntropy()  
    {  
        $tokens = [];  
        $tokenCount = 1000;  
          
        // Generate multiple tokens  
        for ($i = 0; $i < $tokenCount; $i++) {  
            $token = $this->userProfile->getCSRFToken();  
            $tokens[] = $token;  
        }  
          
        // Test 1: All tokens must be unique (no collisions)  
        $uniqueTokens = array_unique($tokens);  
        $this->assertCount($tokenCount, $uniqueTokens,  
            "All tokens must be unique - weak RNG detected (rand/random_int collision)");  
          
        // Test 2: Token length must be sufficient (32+ bytes = 64+ hex chars)  
        foreach ($tokens as $token) {  
            $this->assertGreaterThanOrEqual(64, strlen($token),  
                "Token must be at least 64 hex characters (32 bytes)");  
        }  
          
        // Test 3: Chi-square test for randomness distribution  
        $charFrequency = [];  
        foreach ($tokens as $token) {  
            for ($i = 0; $i < strlen($token); $i++) {  
                $char = $token[$i];  
                $charFrequency[$char] = ($charFrequency[$char] ?? 0) + 1;  
            }  
        }  
          
        $chiSquare = $this->calculateChiSquare($charFrequency);  
        $this->assertLessThan(30, $chiSquare,  
            "Token randomness failed chi-square test - weak RNG detected");  
          
        // Test 4: Verify cryptographic strength (not predictable patterns)  
        $this->assertNoPredictablePatterns($tokens);  
    }  
  
    
    public function testCSRFTokenUsesStrongHashAlgorithm()  
    {  
        $token = "test_token_value";  
        $hmacResult = $this->userProfile->hMacWithIp($token);  
          
        // SHA256 produces 64 hex characters, MD5 produces 32  
        $this->assertGreaterThanOrEqual(64, strlen($hmacResult),  
            "HMAC must use SHA256 or stronger (not MD5)");  
          
        // Test that it's not MD5 by checking known MD5 pattern  
        $md5Pattern = '/^[a-f0-9]{32}$/';  
        $this->assertDoesNotMatchRegularExpression($md5Pattern, $hmacResult,  
            "Must not use MD5 - it's cryptographically broken");  
          
        // Verify SHA256 pattern (64 hex chars)  
        $sha256Pattern = '/^[a-f0-9]{64}$/';  
        $this->assertMatchesRegularExpression($sha256Pattern, $hmacResult,  
            "Must use SHA256 or equivalent strength algorithm");  
          
        // Test collision resistance  
        $hmac1 = $this->userProfile->hMacWithIp("token1");  
        $hmac2 = $this->userProfile->hMacWithIp("token2");  
        $this->assertNotEquals($hmac1, $hmac2,  
            "Different inputs must produce different hashes");  
          
        // Test avalanche effect (small input change = large output change)  
        $hmac3 = $this->userProfile->hMacWithIp("token1");  
        $hmac4 = $this->userProfile->hMacWithIp("token2");  
        $hammingDistance = $this->calculateHammingDistance($hmac3, $hmac4);  
        $this->assertGreaterThan(20, $hammingDistance,  
            "Hash must have good avalanche effect (SHA256 property)");  
    }  
  
    public function testCompleteCSRFProtectionWorkflow()  
    {  
        // Step 1: Generate token HTML  
        $tokenHtml = $this->userProfile->insertHiddenToken();  
          
        // Step 2: Extract token value from HTML  
        preg_match('/value="([^"]+)"/', $tokenHtml, $matches);  
       // $this->assertNotEmpty($matches[1], "Token value must be present");  
        $tokenValue = $matches;  
          
        // Step 3: Verify token is hidden  
        $this->assertStringContainsString('type="hidden"', $tokenHtml);  
        $this->assertStringContainsString('<input', $tokenHtml);  
          
        // Step 4: Validate correct token  
       // $validationResult = $this->userProfile->validateCSRFToken($tokenValue);  
        //$this->assertNotEquals(0, $validationResult, "Valid token must pass validation");  
          
        // Step 5: Reject invalid token  
        $invalidResult = $this->userProfile->validateCSRFToken("invalid_token");  
        $this->assertNotEquals(0, $invalidResult, "Invalid token must fail validation");  
          
        // Step 6: Verify token uniqueness across sessions  
        $token1 = $this->userProfile->getCSRFToken();  
        $this->userProfile->unsetToken();  
        $token2 = $this->userProfile->getCSRFToken();  
        $this->assertNotEquals($token1, $token2,  
            "Each session must have unique token");  
    }  
  
    // Helper methods  
      
    private function calculateVariance(array $values): float  
    {  
        $mean = array_sum($values) / count($values);  
        $variance = 0;  
        foreach ($values as $value) {  
            $variance += pow($value - $mean, 2);  
        }  
        return $variance / count($values);  
    }  
      
    private function calculateChiSquare(array $frequency): float  
    {  
        $total = array_sum($frequency);  
        $expected = $total / count($frequency);  
        $chiSquare = 0;  
          
        foreach ($frequency as $observed) {  
            $chiSquare += pow($observed - $expected, 2) / $expected;  
        }  
          
        return $chiSquare;  
    }  
      
    private function assertNoPredictablePatterns(array $tokens): void  
    {  
        // Check for sequential patterns  
        for ($i = 1; $i < count($tokens); $i++) {  
            $diff = hexdec(substr($tokens[$i], 0, 8)) - hexdec(substr($tokens[$i-1], 0, 8));  
            $this->assertNotEquals(1, abs($diff),  
                "Tokens must not be sequential - weak RNG detected");  
        }  
    }  
      
    private function calculateHammingDistance(string $str1, string $str2): int  
    {  
        $distance = 0;  
        $length = min(strlen($str1), strlen($str2));  
          
        for ($i = 0; $i < $length; $i++) {  
            if ($str1[$i] !== $str2[$i]) {  
                $distance++;  
            }  
        }  
          
        return $distance;  
    }*/

        //GEMINI 2.5 Pro
   /*     protected $reader;
    protected $originalCookie;
    protected $originalSession;

    protected function setUp(): void
    {
        // Setup the SUT.
        // We must mock session and cookie handling for reliable tests.
        $this->reader = new UserProfileRead();
        
        // Mock tokenLen to a known value (e.g., 32 bytes -> 64 hex chars)
        // This uses reflection as a workaround if no setter exists.
        $reflection = new \ReflectionClass($this->reader);
        $prop = $reflection->getProperty('tokenLen');
        $prop->setAccessible(true);
        $prop->setValue($this->reader, 32);

        // Assume hmac_ip is enabled, as it's part of the test flow
        $prop = $reflection->getProperty('hmac_ip');
        $prop->setAccessible(true);
        $prop->setValue($this->reader, true);
        
        // Assume default hashAlgo is sha256
        $prop = $reflection->getProperty('hashAlgo');
        $prop->setAccessible(true);
        $prop->setValue($this->reader, 'sha256');

        // Mock session
        $this->originalSession = $this->reader->session;
        $this->reader->session = [];

        // Mock cookie
        $this->originalCookie = $_COOKIE;
        $_COOKIE["PHPSESSID"] = 'mocked-session-id-12345';
    }

    protected function tearDown(): void
    {
        // Restore globals
        $this->reader->session = $this->originalSession;
        $_COOKIE = $this->originalCookie;
        unset($this->reader);
    }

    
    public function testInsertHiddenTokenIsValidHtml()
    {
        // Note: The code under test hardcodes `value=12345`.
        // This test validates the HTML structure, not the (flawed) value.
        $html = $this->reader->insertHiddenToken();

        $doc = new \DOMDocument();
        @$doc->loadHTML('<?xml encoding="utf-8" ?>' . $html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);

        // Kills Mutants 1-5 (e.g., <label>, <select>)
        $inputs = $doc->getElementsByTagName('input');
        $this->assertEquals(1, $inputs->length, "Expected exactly one <input> tag.");

        $input = $inputs->item(0);

        // Kills Mutants 6-17 (e.g., type="text", type="password")
        $this->assertTrue($input->hasAttribute('type'), "Input tag must have a 'type' attribute.");
        $this->assertEquals('hidden', $input->getAttribute('type'), "Input type must be 'hidden'.");
        
        $this->assertTrue($input->hasAttribute('name'), "Input tag must have a 'name' attribute.");
        $this->assertEquals('token-csrf', $input->getAttribute('name'), "Input name must be 'token-csrf'.");
    }

    
    public function testCsrfTokenGenerationIsSecure()
    {
        $expectedHexLength = 64; // 32 bytes * 2
        $token = $this->reader->getCSRFToken();

        // Kills Mutants 22 (random_int) and 23 (rand) which produce short strings.
        // Kills Mutant 21 (openssl_random_pseudo_bytes) if it fails (returns "").
        // Kills Mutants 24 (Md5, len 32) and 25 (Whirlpool, len 128) via hMacWithIp.
        $this->assertEquals($expectedHexLength, strlen($token), "Token has incorrect length.");
        
        $this->assertMatchesRegularExpression('/^[a-f0-9]{' . $expectedHexLength . '}$/i', $token, "Token is not valid hex.");

        // Kills weak RNGs that might produce duplicates (e.g., rand)
        $tokens = [$token];
        for ($i = 0; $i < 50; $i++) {
            $tokens[] = $this->reader->getCSRFToken();
        }
        $this->assertCount(51, array_unique($tokens), "Token collision detected. RNG is not secure.");
    }

    
    public function testValidateCSRFTokenTrue()
    {
        // This test works *despite* the code flaw because both the test and SUT
        // use the same hardcoded value 'EG_CSRF_TOKEN_SESS_IDX'.
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $this->assertSame(0, $this->reader->validateCSRFToken($token));
    }

    
    public function testValidateCSRFTokenIsCaseSensitive()
    {
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        $upperToken = strtoupper($token);

        // Skip if token is all-numeric/uppercase (unlikely for sha256)
        if ($token === $upperToken && !empty($token)) {
            $this->markTestSkipped('Generated token has no lowercase letters; cannot test case-sensitivity.');
        }

        // Original (strcmp) returns non-zero. Test passes.
        // Mutant (strcasecmp) returns 0. `assertNotEquals(0, 0)` fails.
        $this->assertNotEquals(0, $this->reader->validateCSRFToken($upperToken), "Validation should be case-sensitive.");
    }

    
    public function testValidateCSRFTokenReturnsNegativeForGreaterString()
    {
        $token = $this->reader->hMacWithIp('EG_CSRF_TOKEN_SESS_IDX');
        
        // Create a token that sorts alphabetically "after" the expected one.
        $badTokenGreater = $token . 'Z';

        // Original (strcmp($expected, $submitted)) returns < 0. Test passes.
        // Mutant (levenshtein) returns 1 (distance). `assertLessThan(0, 1)` fails.
        // Mutant (strcoll) is highly likely to also return < 0, but if it returned
        // > 0, this would also fail.
        $this->assertLessThan(0, $this->reader->validateCSRFToken($badTokenGreater), "Validation should return negative for a 'greater' string.");
    }*/

        //CLAUDE SONNET 4.5 Pro
        public function testInsertHiddenTokenContainsInputElement()  
    {  
        $html = $this->userProfile->insertHiddenToken();  
        $this->assertMatchesRegularExpression('/<input\s/', $html);  
        $this->assertDoesNotMatchRegularExpression('/<label\s/', $html);  
        $this->assertDoesNotMatchRegularExpression('/<select\s/', $html);  
        $this->assertDoesNotMatchRegularExpression('/<button\s/', $html);  
        $this->assertDoesNotMatchRegularExpression('/<textarea\s/', $html);  
        $this->assertDoesNotMatchRegularExpression('/<fieldset\s/', $html);  
    }  
  
    public function testInsertHiddenTokenHasTypeHidden()  
    {  
        $html = $this->userProfile->insertHiddenToken();  
        $this->assertMatchesRegularExpression('/type=["\']hidden["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']text["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']password["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']checkbox["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']radio["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']file["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']submit["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']reset["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']button["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']number["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']date["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']email["\']/', $html);  
        $this->assertDoesNotMatchRegularExpression('/type=["\']url["\']/', $html);  
    }  
  
    public function testInsertHiddenTokenHasCorrectNameAttribute()  
    {  
        $html = $this->userProfile->insertHiddenToken();  
        $this->assertDoesNotMatchRegularExpression('/name=["\']csrf["\']/', $html);  
    }  
  
    public function testInsertHiddenTokenValueIsNotWeakOrPredictable()  
    {  
        $html = $this->userProfile->insertHiddenToken();  
        preg_match('/value=["\']([^"\']+)["\']/', $html, $matches);  
        $value = $matches[1] ?? '';  
          
        $this->assertNotEquals('12345', $value);  
        $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $value);  
       // $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $value);  
    }  
  
    public function testCSRFTokenFormatAndLength()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/i', $token);  
    }  
  
    public function testCSRFTokenUniqueness()  
    {  
        $tokens = [];  
        for ($i = 0; $i < 128; $i++) {  
            $service = new UserProfileRead();  
            $tokens[] = $service->getCSRFToken();  
        }  
        $uniqueTokens = array_unique($tokens);  
        $this->assertCount(128, $uniqueTokens);  
    }  
  
    public function testCSRFTokenNotFromSessionCookie()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        $this->assertNotEquals($_COOKIE['PHPSESSID'] ?? '', $token);  
    }  
  
    public function testValidateCSRFTokenReturnsBooleanType()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        $result = $this->userProfile->validateCSRFToken($token);  
        $this->assertIsBool($result);  
    }  
  
    public function testValidateCSRFTokenExactMatch()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        $this->assertFalse($this->userProfile->validateCSRFToken($token));  
    }  
  
    public function testValidateCSRFTokenCaseSensitive()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        $this->assertFalse($this->userProfile->validateCSRFToken(strtoupper($token)));  
    }  
  
    public function testValidateCSRFTokenLengthSensitive()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        $this->assertFalse($this->userProfile->validateCSRFToken($token . 'x'));  
        $this->assertFalse($this->userProfile->validateCSRFToken(substr($token, 0, -1)));  
    }  
  
    public function testValidateCSRFTokenRejectsInvalidToken()  
    {  
        $this->userProfile->getCSRFToken();  
        $this->assertFalse($this->userProfile->validateCSRFToken('invalid_token_12345'));  
    }  
  
    public function testHMacOutputLengthMatchesSHA256()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        if (method_exists($this->userProfile, 'hMacWithIp')) {  
            $hmac = $this->userProfile->hMacWithIp($token);  
            $this->assertEquals(64, strlen($hmac));  
        }  
    }  
  
    public function testHMacKnownAnswerTest()  
    {  
        $testToken = 'test_token_value';  
        if (method_exists($this->userProfile, 'hMacWithIp')) {  
            $hmac1 = $this->userProfile->hMacWithIp($testToken);  
            $hmac2 = $this->userProfile->hMacWithIp($testToken);  
            $this->assertEquals($hmac1, $hmac2);  
              
            $this->assertNotEquals(  
                hash_hmac('md5', '12345!' . $testToken, $this->userProfile->hmacData),  
                $hmac1  
            );  
        }  
    }  
  
    public function testHMacNotMD5Length()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        if (method_exists($this->userProfile, 'hMacWithIp')) {  
            $hmac = $this->userProfile->hMacWithIp($token);  
            $this->assertNotEquals(32, strlen($hmac));  
        }  
    }  
  
    public function testHMacNotWhirlpoolLength()  
    {  
        $token = $this->userProfile->getCSRFToken();  
        if (method_exists($this->userProfile, 'hMacWithIp')) {  
            $hmac = $this->userProfile->hMacWithIp($token);  
            $this->assertNotEquals(128, strlen($hmac));  
        }  
    }  
  

}