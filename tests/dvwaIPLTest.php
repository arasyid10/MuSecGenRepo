<?php
declare(strict_types=1);

namespace Tests;

use App\dvwaipl;
use PHPUnit\Framework\TestCase;

final class DvwaiplTest extends TestCase
{
    private string $uploadDir;
     private string $targetDir;
    private array $createdTempFiles = [];
    protected function setUp(): void
    {
        $_GET = [];
        $_POST = [];
        $_FILES = [];
        $_SESSION = [];
        $this->uploadDir = dirname(__DIR__) . '/src/../vulnerable_files/';
        if (!is_dir($this->uploadDir)) {
            mkdir($this->uploadDir, 0777, true);
        }

        // bersihkan folder upload
        foreach (glob($this->uploadDir . '*') as $f) {
            @unlink($f);
        }
    }

    public function testDvwaFI_AllowsWhitelistedPage(): void
    {
        $sut = new dvwaipl();
        $_GET['page'] = 'file1.php';

        $ok = $sut->dvwaFI();

        $this->assertTrue($ok);
        $this->assertSame('', $sut->getHtml());
    }

    public function testDvwaFI_BlocksNonWhitelistedPage(): void
    {
        $sut = new dvwaipl();
        $_GET['page'] = 'evil.php';

        $ok = $sut->dvwaFI();

        $this->assertFalse($ok);
        $this->assertStringContainsString('ERROR: File not found!', $sut->getHtml());
    }

    public function testDvwaUpload_NoOpWhenNoPostFlag(): void
    {
        $sut = new dvwaipl();

        $sut->dvwaUpload();

        $this->assertSame('', $sut->getHtml());
    }
   
    public function testDvwaUpload_InvalidFileShowsErrorMessage(): void
    {
        $sut = new dvwaipl();
        $_POST['Upload'] = '1';

        // Simulasikan file upload yang tidak valid (mis. .php)
        $_FILES['uploaded'] = [
            'name' => 'shell.php',
            'size' => 10,
            'type' => 'application/x-php',
            'tmp_name' => "C:\\TatapMuka.jpg", // ada file beneran, tapi getimagesize akan gagal
        ];

        $sut->dvwaUpload();

        $this->assertStringContainsString(
            'We can only accept JPEG or PNG images',
            $sut->getHtml()
        );
    }

    public function testDvwaUpload_ValidFileShowsSuccessMessage(): void
    {
        $sut = new dvwaipl();
        $_POST['Upload'] = '1';

        // Simulasikan file upload yang valid (mis. .png)
        $_FILES['uploaded'] = [
            'name' => 'TatapMuka.jpg',
            'size' => 1000,
            'type' => 'image/jpeg',
            'tmp_name' => __DIR__ . DIRECTORY_SEPARATOR . 'TatapMuka.jpg', // ada file beneran, tapi getimagesize akan gagal
        ];

        $sut->dvwaUpload();

        $this->assertStringContainsString(
            'Berhasil Upload',
            $sut->getHtml()
        );
    }
       
    
 public function testUploadDirExists(): void
    {
        $this->assertDirectoryExists($this->uploadDir);
    }
    public function testUpdloadTrue(): void
    {
        $this->assertTrue(is_dir($this->uploadDir));
    }
    public function testClearHTML(): void
    {
        $sut = new dvwaipl();
        $_POST['Upload'] = '1';

        // Simulasikan file upload yang tidak valid (mis. .php)
        $_FILES['uploaded'] = [
            'name' => 'shell.php',
            'size' => 10,
            'type' => 'application/x-php',
            'tmp_name' => __FILE__, // ada file beneran, tapi getimagesize akan gagal
        ];

        $sut->dvwaUpload();
        $this->assertStringContainsString(
            'We can only accept JPEG or PNG images',
            $sut->getHtml()
        );
        $sut->clearHtml();
        $this->assertSame('', $sut->getHtml());
    }
}
