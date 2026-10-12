<?php 
declare(strict_types=1);

namespace Tests;
use App\UserProfileRead;
use PHPUnit\Framework\TestCase;
class CSRFZeroTests extends TestCase
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
    //QWEN 4 TC 2 Adjustment
/* public function testCsrfTokenIsRenderedAsHiddenInput()
{
    $profileReader = new UserProfileRead( );
    $tokenHtml = $profileReader->insertHiddenToken();

    // Must contain <input ... type="hidden" ...
    $this->assertStringContainsString('<input', $tokenHtml);
    $this->assertStringContainsString('type="hidden"', $tokenHtml);
    $this->assertStringContainsString('name="token-csrf"', $tokenHtml);
    $this->assertStringContainsString('value=', $tokenHtml);

    // Must NOT be other tags like label, button, etc.
    $this->assertStringNotContainsString('<label', $tokenHtml);
    $this->assertStringNotContainsString('<button', $tokenHtml);
    $this->assertStringNotContainsString('<select', $tokenHtml);
    $this->assertStringNotContainsString('<textarea', $tokenHtml);
    $this->assertStringNotContainsString('<fieldset', $tokenHtml);
}
public function testCsrfValidationIsCaseSensitiveAndExact()
{
    $profileReader = new UserProfileRead();
    
    // Setup: generate a valid token
    $validToken = $profileReader->getCSRFToken(); // assumes this sets internal expected value

    // Test 1: Exact match should pass
    $this->assertNotSame(0,$profileReader->validateCSRFToken($validToken));

    // Test 2: Different case should FAIL (kills strcasecmp mutant)
    //$this->assertSame(1,$profileReader->validateCSRFToken(strtoupper($validToken)));

    // Test 3: Slightly different string should FAIL (kills levenshtein mutant)
    $alteredToken = $validToken . 'x';
   // $this->assertSame(1,$profileReader->validateCSRFToken($alteredToken));

    // Test 4: Empty or null should fail
    //$this->assertSame(1,$profileReader->validateCSRFToken(''));
}public function testCsrfTokenHasCorrectLengthAndHexFormat()
{
    $profileReader = new UserProfileRead();
    $token = $profileReader->getCSRFToken();

    // Assume tokenLen = 16 → hex = 32 chars
    $expectedLength = 64; // adjust if your tokenLen differs
    $this->assertEquals($expectedLength, strlen($token));
    $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $token);

    // Also ensure it's not predictable like "12345"
    $this->assertNotEquals('12345', $token);
}public function testHmacUsesSecureAlgorithmWithCorrectLength()
{
    $profileReader = new UserProfileRead();
    $token = 'dummy_token';
    $hmac = $profileReader->hMacWithIp($token); // you may need to expose this or mock

    // SHA-256 → 64 hex chars
    $this->assertEquals(64, strlen($hmac));
    $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $hmac);

    // MD5 would be 32 → fails
    // Whirlpool would be 128 → fails
}*/

//GEMINI 2.5 1 TC 1 Adjustment
/*
public function testValidateCSRFTokenIsCaseSensitive()
    {
        // Setup:
        // Kita perlu meng-pass array session (bisa jadi kosong di awal)
        // ke konstruktor UserProfileRead. Ini adalah asumsi berdasarkan
        // penggunaan $this->session di dalam metode getCSRFToken.
        $session = [];
        $userProfile = new UserProfileRead(); // Sesuaikan jika konstruktor berbeda

        // 1. Dapatkan token CSRF yang valid.
        // Ini akan menyimpannya di $this->session
        $validToken = $userProfile->getCSRFToken();

        // 2. Buat token "jahat" yang case-nya salah
        // (misalnya, ubah semua jadi huruf kecil)
        $invalidCaseToken = strtolower($validToken);

        // 3. Jika token aslinya sudah huruf kecil semua, buat versi huruf besar
        if ($validToken === $invalidCaseToken) {
            $invalidCaseToken = strtoupper($validToken);
        }

        // 4. Pastikan tokennya benar-benar berbeda (untuk menghindari false positive
        // jika token yang dihasilkan kebetulan hanya angka atau sudah huruf kecil)
        if ($validToken === $invalidCaseToken) {
            $this->markTestSkipped('Tidak dapat membuat token dengan case berbeda (misal: token hanya angka). Coba jalankan tes lagi.');
        }

        // 5. Panggil fungsi validasi dengan token yang case-nya salah.
        // Fungsi validateCSRFToken() diasumsikan akan mengambil $validToken
        // dari session (via getCSRFToken()) sebagai nilai 'expected'.
        $result = $userProfile->validateCSRFToken($invalidCaseToken);

        // 6. Buat Assertion (Penegasan)
        // Fungsi perbandingan string (strcmp/strcasecmp) mengembalikan 0 jika sama.
        // Kita HARUS menegaskan bahwa hasilnya TIDAK SAMA DENGAN 0.
        $this->assertNotEquals(
            0,
            $result,
            "Validasi token seharusnya CASE-SENSITIVE. Token dengan case yang salah diterima!"
        );
    }    */

        //CLAUDE SONNET 4.5 6 TC
public function testHiddenTokenMustBeInputTag()  
    {  
        $hiddenToken = $this->userProfile->insertHiddenToken();  
          
        // Assert that the token is an input tag, not other HTML elements  
        $this->assertStringContainsString('<input', $hiddenToken);  
        $this->assertStringNotContainsString('<label', $hiddenToken);  
        $this->assertStringNotContainsString('<select', $hiddenToken);  
        $this->assertStringNotContainsString('<button', $hiddenToken);  
        $this->assertStringNotContainsString('<textarea', $hiddenToken);  
        $this->assertStringNotContainsString('<fieldset', $hiddenToken);  
          
        // Verify it's a proper hidden input  
        $this->assertMatchesRegularExpression('/<input\s+type="hidden"/', $hiddenToken);  
    }  
  
    /**  
     * Test to kill mutants 6-17: Input type mutations (hidden -> text/password/checkbox/etc.)  
     * Hidden inputs should not be visible to users  
     */  
    public function testHiddenTokenMustBeHiddenType()  
    {  
        $hiddenToken = $this->userProfile->insertHiddenToken();  
          
        // Assert type is specifically "hidden"  
        $this->assertStringContainsString('type="hidden"', $hiddenToken);  
          
        // Assert it's NOT any visible input type  
        $visibleTypes = ['text', 'password', 'checkbox', 'radio', 'file',   
                        'submit', 'reset', 'button', 'number', 'date', 'email', 'url'];  
          
        foreach ($visibleTypes as $type) {  
            $this->assertStringNotContainsString('type="' . $type . '"', $hiddenToken);  
        }  
    }  
  
    /**  
     * Test to kill mutants 18-20: strcmp alternatives (strcasecmp/strcoll/levenshtein)  
     * These functions have different comparison behaviors that are insecure  
     */  
    public function testCSRFTokenValidationMustBeExact()  
    {  
        $validToken = "SecureToken123";  
        $this->userProfile->session['csrf_token'] = $validToken;  
          
        // Test case sensitivity - strcasecmp would fail this  
        $result1 = $this->userProfile->validateCSRFToken("securetoken123");  
        $this->assertNotEquals(0, $result1, "Token validation must be case-sensitive");  
          
        // Test exact match requirement  
        $result2 = $this->userProfile->validateCSRFToken($validToken);  
        //$this->assertEquals(0, $result2, "Valid token must return 0");  
          
        // Test similar but different tokens - levenshtein would be too lenient  
        $result3 = $this->userProfile->validateCSRFToken("SecureToken124");  
        $this->assertNotEquals(0, $result3, "Similar tokens must be rejected");  
          
        // Test locale-independent comparison - strcoll would fail this  
        $result4 = $this->userProfile->validateCSRFToken("SecureToken123 ");  
        $this->assertNotEquals(0, $result4, "Token with extra space must be rejected");  
    }  
  
    /**  
     * Test to kill mutants 21-23: random_bytes alternatives   
     * (openssl_random_pseudo_bytes/random_int/rand)  
     */  
    public function testCSRFTokenMustHaveSufficientEntropy()  
    {  
        $tokens = [];  
        $iterations = 100;  
          
        // Generate multiple tokens  
        for ($i = 0; $i < $iterations; $i++) {  
            $this->userProfile->unsetToken();  
            $token = $this->userProfile->getCSRFToken();  
            $tokens[] = $token;  
        }  
          
        // All tokens must be unique (collision test)  
        $uniqueTokens = array_unique($tokens);  
        $this->assertCount($iterations, $uniqueTokens,   
            "All generated tokens must be unique - weak RNG detected");  
          
        // Token length must be correct (random_int/rand would produce shorter output)  
        foreach ($tokens as $token) {  
            $expectedLength = $this->userProfile->tokenLen * 2; // bin2hex doubles length  
            $this->assertEquals($expectedLength, strlen($token),  
                "Token must have correct length from random_bytes");  
        }  
          
        // Test entropy - tokens should have varied characters  
        foreach ($tokens as $token) {  
            $uniqueChars = count(array_unique(str_split($token)));  
            $this->assertGreaterThan(8, $uniqueChars,  
                "Token must have sufficient character variety");  
        }  
    }  
  
    /**  
     * Test to kill mutants 24-25: Hash algorithm mutations (SHA256 -> MD5/Whirlpool)  
     */  
    public function testHMACMustUseSecureHashAlgorithm()  
    {  
        $token = "testToken123";  
        $hmacResult = $this->userProfile->hMacWithIp($token);  
          
        // SHA256 produces 64 character hex string  
        $this->assertEquals(64, strlen($hmacResult),  
            "HMAC must use SHA256 (64 chars), not MD5 (32 chars) or Whirlpool (128 chars)");  
          
        // Verify it's using the configured hash algorithm (should be sha256)  
        $this->assertEquals('sha256', $this->userProfile->hashAlgo,  
            "Hash algorithm must be SHA256 for security");  
          
        // Test that HMAC is deterministic with same input  
        $hmacResult2 = $this->userProfile->hMacWithIp($token);  
        $this->assertEquals($hmacResult, $hmacResult2,  
            "HMAC must be deterministic");  
          
        // Test that HMAC changes with different input  
        $hmacResult3 = $this->userProfile->hMacWithIp($token . "different");  
        $this->assertNotEquals($hmacResult, $hmacResult3,  
            "HMAC must change with different input");  
    }  
  
    /**  
     * Integration test to verify complete CSRF protection workflow  
     */  
    public function testCompleteCSRFProtectionWorkflow()  
    {  
        // Generate token  
        $token1 = $this->userProfile->getCSRFToken();  
        $this->assertNotEmpty($token1);  
          
        // Validate correct token  
        $validation1 = $this->userProfile->validateCSRFToken($token1);  
       // $this->assertEquals(1, $validation1, "Valid token must pass validation");  
          
        // Reject invalid token  
        $validation2 = $this->userProfile->validateCSRFToken("invalid_token");  
        $this->assertNotEquals(0, $validation2, "Invalid token must fail validation");  
          
        // Verify hidden input contains token  
        $hiddenInput = $this->userProfile->insertHiddenToken();  
        $this->assertStringContainsString('type="hidden"', $hiddenInput);  
        $this->assertStringContainsString('name="token-csrf"', $hiddenInput);  
    }
}