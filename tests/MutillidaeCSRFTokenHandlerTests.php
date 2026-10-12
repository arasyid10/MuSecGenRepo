<?php
namespace Tests;
use App\mutillidaeCSRFTokenHandler;
use PHPUnit\Framework\TestCase;

//require_once __DIR__ . '/../src/mutillidaeCSRFTokenHandler.php';

class MutillidaeCSRFTokenHandlerTests extends TestCase {

protected mutillidaeCSRFTokenHandler $reader;
    protected function setUp(): void {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        $_SESSION = [];
        $this->reader = new mutillidaeCSRFTokenHandler("1", "register-user");
    }

    /** @test */
    public function it_rejects_invalid_csrf_token_when_security_is_enabled() {
        $page = 'register-user';

        $handler = new mutillidaeCSRFTokenHandler("1", $page);

        // Generate token asli
        $handler->generateCSRFToken();

        // Token palsu
        $fakeToken = 'INVALID_TOKEN';

        $result = $handler->validateCSRFToken($fakeToken);

        $this->assertFalse($result);
    }

    /** @test */
    public function it_always_returns_true_when_csrf_protection_is_disabled() {
        $page = 'register-user';

        // Security level 0 → CSRF OFF
        $handler = new mutillidaeCSRFTokenHandler("0", $page);

        $result = $handler->validateCSRFToken('anything');

        $this->assertTrue($result);
    }

    /** @test */
public function setSecurityLevel_zero_produces_empty_csrf_token() {
    $page = 'test-page';

    $handler = new mutillidaeCSRFTokenHandler("1", $page);

    // Ubah security level ke 0
    $handler->setSecurityLevel("0");

    $token = $handler->generateCSRFToken();

    $this->assertSame("", $token);
}
/** @test */
public function low_security_level_generates_incremental_token() {
    $page = 'test-page';

    // Simulasi token sebelumnya
    $_SESSION[$page]['csrf-token'] = 10;

    $handler = new mutillidaeCSRFTokenHandler("1", $page);

    $token = $handler->generateCSRFToken();

    // 77 + 10 = 87
    $this->assertSame(87, $token);
}
/** @test */
public function high_security_level_generates_non_empty_random_token() {
    $page = 'test-page';

    $handler = new mutillidaeCSRFTokenHandler("5", $page);

    $token = $handler->generateCSRFToken();

    $this->assertNotEmpty($token);
    $this->assertIsString($token);
}
/** @test */
public function high_security_level_generates_different_tokens_each_time() {
    $page = 'test-page';

    $handler = new mutillidaeCSRFTokenHandler("5", $page);

    $token1 = $handler->generateCSRFToken();
    $token2 = $handler->generateCSRFToken();
    echo $token1."\n,token 2:";
    echo $token2;
    $this->assertNotSame($token1, $token2);
}
/** @test */
public function changing_security_level_changes_token_behavior() {
    $page = 'test-page';

    $handler = new mutillidaeCSRFTokenHandler("0", $page);
    $tokenNone = $handler->generateCSRFToken();

    $handler->setSecurityLevel("1");
    $_SESSION[$page]['csrf-token'] = 5;
    $tokenLow = $handler->generateCSRFToken();

    $handler->setSecurityLevel("5");
    $tokenHigh = $handler->generateCSRFToken();

    $this->assertSame("", $tokenNone);
    $this->assertSame(82, $tokenLow); // 77 + 5
    $this->assertNotEmpty($tokenHigh);
}


// TAMBAHAN
/** @test */
    public function high_security_token_decodes_to_exactly_64_bytes(): void
    {
        $page = 'test-page';
        $handler = new mutillidaeCSRFTokenHandler("5", $page);

        $token = $handler->generateCSRFToken();

        // base64_decode strict mode: false jika bukan base64 valid
        $decoded = base64_decode($token, true);

        $this->assertNotFalse($decoded, 'Token harus valid base64');

        // INI KUNCI: random_bytes(64) -> base64_decode(token) harus tepat 64 bytes
        // Mutant random_int/rand -> base64 dari "0..64" -> decoded length kecil (1-2 bytes), akan gagal di sini.
        $this->assertSame(64, strlen($decoded), 'Decoded token harus 64 bytes');
    }

    /** @test */
    public function high_security_token_has_expected_base64_length_and_padding(): void
    {
        $page = 'test-page';
        $handler = new mutillidaeCSRFTokenHandler("5", $page);

        $token = $handler->generateCSRFToken();

        // 64 bytes => base64 length = 4*ceil(64/3) = 88, dan padding "=="
        $this->assertSame(88, strlen($token), 'Panjang base64 untuk 64 bytes harus 88 karakter');
        $this->assertStringEndsWith('==', $token, 'Base64 64 bytes harus berakhiran "=="');
    }
}
