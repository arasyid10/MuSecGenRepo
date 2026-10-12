<?php
namespace Tests;
use PHPUnit\Framework\TestCase;
use App\dvwacsrf;

class DvwaCsrfTokenTests extends TestCase
{
     protected dvwacsrf $reader;
    protected function setUp(): void
    {
        $_SESSION = [];
        $this->reader = new dvwacsrf();
    }
/*public function testHiddenValue() {
    $pattern = $this->reader->insertHiddenToken();
    //$str = '<input type="hidden" name="token-csrf" value='. $_COOKIE["PHPSESSID"] .'>';
    $str = '<input type="hidden" name="token-csrf" value=12345 />';
    //$this->assertMatchesRegularExpression($pattern, $str);
   $this->assertNotEmpty($pattern);//Pakai ini MSI TURUN Karena Weak
}
 
        public function testTestAja(): void
    {

        $result = $this->reader->testAja();
        $this->assertEquals(25, $result);
    }

         public function testGenerateSessionToken(): void
    {
        $this->reader->generateSessionToken();

        $this->assertArrayHasKey('session_token', $_SESSION);
        $this->assertNotEmpty($_SESSION['session_token']);
    }

    public function testDestroySessionToken(): void
    {
        $_SESSION['session_token'] = 'dummy';
        $this->reader->destroySessionToken();

        $this->assertArrayNotHasKey('session_token', $_SESSION);
    }

    public function testTokenFieldContainsToken(): void
    {
        $_SESSION['session_token'] = 'abc123';

        $html = $this->reader->tokenField();

        $this->assertStringContainsString("user_token", $html);
        $this->assertStringContainsString("abc123", $html);
    }

    public function testCheckTokenDesignLimitation(): void
    {
        $this->assertTrue(true);
    }

*/

    //NEW TEST CASE
    /** @test */
    public function dvwaSessionGrab_creates_dvwa_session_if_not_exists()
    {
        $session = $this->reader->dvwaSessionGrab();

        $this->assertIsArray($session);
        $this->assertArrayHasKey('dvwa', $_SESSION);
    }
    /** @test */
    public function dvwaMessagePush_adds_message_to_session()
    {
        $this->reader->dvwaMessagePush('CSRF token is incorrect');

        $this->assertEquals(
            ['CSRF token is incorrect'],
            $_SESSION['dvwa']['messages']
        );
    }
    /** @test */
    public function generateSessionToken_creates_session_token()
    {
        $this->reader->generateSessionToken();

        $this->assertArrayHasKey('session_token', $_SESSION);
        $this->assertNotEmpty($_SESSION['session_token']);
    }
     /** @test */
    public function destroySessionToken_removes_token()
    {
        $_SESSION['session_token'] = 'dummy';

        $this->reader->destroySessionToken();

        $this->assertArrayNotHasKey('session_token', $_SESSION);
    }

    /** @test */
    public function tokenField_returns_hidden_input_with_session_token()
    {
        $_SESSION['session_token'] = 'abc123';

        $field = $this->reader->tokenField();

        $this->assertStringContainsString(
            "name='user_token'",
            $field
        );

        $this->assertStringContainsString(
            "value='abc123'",
            $field
        );
    }

    /** @test */
    public function checkToken_passes_when_token_matches()
    {
        $this->reader->checkToken(
            'valid-token',
            'valid-token',
            '/fail'
        );

        $this->assertTrue(true); // no redirect = success
    }
    
    //TAMBAHAN 1
      /** @test */
    public function session_token_must_be_md5_hex_with_exact_length()
    {
        $this->reader->generateSessionToken();
        $token = $_SESSION['session_token'];

        // 1. Panjang harus 32 (MD5)
        $this->assertSame(
            32,
            strlen($token),
            'CSRF token must be 32-character MD5 hash'
        );

        // 2. Harus hex-only
        $this->assertMatchesRegularExpression(
            '/^[a-f0-9]{32}$/i',
            $token,
            'CSRF token must be hexadecimal MD5 format'
        );
    }

    /** @test */
    public function token_field_must_be_hidden_input_element()
    {
        $_SESSION['session_token'] = 'abc123abc123abc123abc123abc123ab';
        $field = $this->reader->tokenField();

        // HARUS <input>
        $this->assertStringContainsString(
            '<input',
            $field,
            'CSRF token field must use input tag'
        );

        // HARUS type hidden
        $this->assertStringContainsString(
            "type='hidden'",
            $field,
            'CSRF token field must be hidden input'
        );

        // TIDAK BOLEH elemen lain
        $this->assertStringNotContainsString('<label', $field);
        $this->assertStringNotContainsString('<select', $field);
        $this->assertStringNotContainsString('<button', $field);
        $this->assertStringNotContainsString('<textarea', $field);
        $this->assertStringNotContainsString('<fieldset', $field);

        // Value token harus ada
        $this->assertStringContainsString(
            $_SESSION['session_token'],
            $field
        );
    }
}
