<?php

namespace Tests;

use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe22PathTraversalTests extends TestCase
{
    protected VulnFileRead $reader;
    private string $baseDir;
   
     private $base;
    protected function setUp(): void
    {
        $this->reader = new VulnFileRead();
        // $this->base = realpath(__DIR__ . '/../vulnerable_files/');
          //$this->basePath = realpath(__DIR__ . '/../vulnerable_files/');
        //   $this->baseDir = realpath(__DIR__ . '/../vulnerable_files/');

        /* Ensure test directory exists
        if (!is_dir($this->baseDir)) {
            mkdir($this->baseDir, 0777, true);
        }
        // Create a legit file for testing
        file_put_contents($this->baseDir . '/legit.txt', "expected content");*/
    }
    
    ```````````public function testPathTraversalEscape(): void
    {
        $attempt = $this->reader->read('../../../../etc/passwd');
        $this->assertStringNotContainsString('root:x:0:0:', $attempt, 'Path traversal should not allow access to /etc/passwd');
    }
      public function testfindPathWeak()
    {
    $basepath = "D:\\Kegiatanku\\S3\\Semester 8\\PPT\\Kelompok 3 IPL\\traversal-vulnerabilities-main\\traversal-vulnerabilities-main\\images";  ;
    $path = $basepath."\\pulau-padar.jpg"; 
    $response =  $this->reader->findPath($path,$basepath);
    $this->assertNotFalse($response);
    }
    public function testabsPathWeak()
    {
    $basepath = __DIR__ ;
    $path = $basepath."\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt"; 
    $response = $this->reader->absPath($path);
    echo "Response=".$response;
    $this->assertNotEmpty($response);
    }
    public function testsecureFilePath()
   {    $basepath = __DIR__ ;
        $path="D:\\Kegiatanku\\S3\\Semester 8\\PPT\\Kelompok 3 IPL\\traversal-vulnerabilities-main\\traversal-vulnerabilities-main\\tests\\..\\config\\another.txt";
        $response = $this->reader->secureFilePath($path,$basepath);
        $this->assertTrue($response);
   }
   
   public function test_valid_subpath_returns_true()
    {
        $basePath = __DIR__ ;
        $inputPath = __DIR__ .'\\CWE352CSRFTests.php';
        $result = $this->reader->isValidSubPath($inputPath, $basePath);
        $this->assertTrue($result);
    }```````````




    //TEST CASE STANDARD PROMPTING 11 TC 3 Adjusment testFindPathCaseSensitive,testIsValidSubPathRequiresRealpath,testAbsPathRejectsInvalidPath
/*
    public function testFindPathCaseSensitive()
    {
        $path = $this->base . DIRECTORY_SEPARATOR . "sample.txt";
        $result = $this->reader->findPath($path, $this->base);
        $this->assertSame(false, $result);
    }

    public function testFindPathMustNotReturnTrueOrZeroConstant()
    {
        $path = $this->base . DIRECTORY_SEPARATOR . "fake.txt";
        $result = $this->reader->findPath($path, $this->base);
        $this->assertNotSame(true, $result);
        $this->assertNotSame(0, $result);
    }

    public function testFindPathRejectsDriveInjection()
    {
        $path = $this->base . DIRECTORY_SEPARATOR . "sample.txt";
        $result = $this->reader->findPath($path, $this->base);
        $this->assertNotSame(strpos($path, 'D:\\'), $result);
    }

    public function testIsValidSubPathRequiresRealpath()
    {
        //$input = $this->base . DIRECTORY_SEPARATOR . "a.txt";
        $input = __DIR__. DIRECTORY_SEPARATOR . "a.txt";
        $result = $this->reader->isValidSubPath($input, __DIR__);
        $this->assertTrue($result);
    }

    public function testReadRejectsPathTraversalPayload()
    {
        $attempt = $this->reader->read('../../../../etc/passwd');
        $this->assertSame('Access denied', $attempt);
    }

    public function testReadValidFileAccess()
    {
        $file = $this->base . DIRECTORY_SEPARATOR . "legit.txt";
        file_put_contents($file, "safecontent");
        $content = $this->reader->read("legit.txt");
        $this->assertSame("safecontent", $content);
        unlink($file);
    }

    public function testAbsPathCanonicalization()
    {
        $file = $this->base . DIRECTORY_SEPARATOR . "a.txt";
        file_put_contents($file, "data");
        $path = $this->base . DIRECTORY_SEPARATOR . ".." . DIRECTORY_SEPARATOR . "vulnerable_files" . DIRECTORY_SEPARATOR . "a.txt";
        $result = $this->reader->absPath($path);
        $this->assertSame(realpath($path), $result);
        unlink($file);
    }

    /*public function testAbsPathRejectsInvalidPath()
    {
        $invalid = __DIR__ . '\\..\\config\\path-payloads.json';;
        $result = $this->reader->absPath($invalid);
        $this->assertFalse($result);
    }//CLOSE DISINI

    public function testSecureFilePathDeniesOutsideBase()
    {
        $response = $this->reader->secureFilePath(__DIR__ . "/../../secret.txt", $this->base);
        $this->assertFalse($response);
    }

    public function testSecureFilePathDeniesNonexistentFile()
    {
        $response = $this->reader->secureFilePath($this->base . "/ghost.txt", $this->base);
        $this->assertFalse($response);
    }

    public function testSecureFilePathRequiresPermission()
    {
        $fakeFile = $this->base . DIRECTORY_SEPARATOR . "perm.txt";
        file_put_contents($fakeFile, "secret");
        $response = $this->reader->secureFilePath($fakeFile, $this->base);
        $this->assertTrue($response);
        unlink($fakeFile);
    }

//TEST CASE STANDARD CYCLE 2, 6 TC 2Adjusment
public function testReadRejectsExternalFilePayloads()
    {
        $attempt1 = $this->reader->read(__DIR__ . '/../../config.ini');
        $attempt2 = $this->reader->read(__DIR__ . '/../../files.txt');
        $attempt3 = $this->reader->read(__DIR__ . '/../../legit.txt');
        $this->assertSame('Access denied', $attempt1);
        $this->assertSame('Access denied', $attempt2);
        $this->assertSame('Access denied', $attempt3);
    }

   /* public function testReadAcceptsOnlyBaseDirectoryFile()
    {
        $content = $this->reader->read('safe.txt');
        $this->assertSame("OK", $content);
    }//CLOSE DISINI

    public function testIsValidSubPathMustUseRealpathCanonicalization()
    {
        $fake = __DIR__ . "/../../outside.txt";
        $result = $this->reader->isValidSubPath($fake, $this->base);
        $this->assertFalse($result);
    }

    public function testIsValidSubPathRejectsConstantTrueMutant()
    {
        $input = __DIR__ . "/../../fake.txt";
        $result = $this->reader->isValidSubPath($input, $this->base);
        $this->assertFalse($result);
    }

    public function testFindPathRejectsCaseInsensitiveAndSubstringVariants()
    {
        $path = $this->base . DIRECTORY_SEPARATOR . "safe.txt";
        $result = $this->reader->findPath($path, $this->base);
        $this->assertSame(false, $result);
        $this->assertNotSame(0, $result);
    }

    public function testSecureFilePathRejectsDriveInjectionAndGuardRemoval()
    {
        $response1 = $this->reader->secureFilePath("D:\\Windows\\system.ini", $this->base);
        $this->assertFalse($response1);

        $response2 = $this->reader->secureFilePath($this->base . "/ghost.txt", $this->base);
        $this->assertFalse($response2);
    }

        //TEST CASE MUTATION CENTRIC 9, 0 Adjustment 
  /*  public function test_read_denies_nonexistent_file()
    {
        $result = $this->reader->read('doesnotexist.txt');
        $this->assertSame('Access denied', $result);
    }

    public function test_read_allows_inside_base_file()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'legit.txt';
        file_put_contents($file, 'SAFE');
        $result = $this->reader->read('legit.txt');
        $this->assertSame('SAFE', $result);
        unlink($file);
    }

    public function test_read_denies_traversal_file()
    {
        $result = $this->reader->read('../../../../etc/passwd');
        $this->assertSame('Access denied', $result);
    }

    public function test_isValidSubPath_returns_true_for_inside_and_false_for_outside()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'inside.txt';
        file_put_contents($file, 'IN');
        $inside = $this->reader->isValidSubPath($file, $this->basePath);
        $this->assertTrue($inside);
        $outside = __DIR__ . '/../../escape.txt';
        $outsideRes = $this->reader->isValidSubPath($outside, $this->basePath);
        $this->assertFalse($outsideRes);
        unlink($file);
    }

    public function test_findPath_consistent_type_and_result()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'fp.txt';
        file_put_contents($file, 'FP');
        $inside = $this->reader->findPath($file, $this->basePath);
        $this->assertIsInt($inside);
        $this->assertNotFalse($inside);
        $outside = __DIR__ . '/../../fake.txt';
        $outRes = $this->reader->findPath($outside, $this->basePath);
        $this->assertFalse($outRes);
        unlink($file);
    }

    public function test_findPath_returns_false_for_invalid_path()
    {
        $path = __DIR__ . '/../../badpath.txt';
        $result = $this->reader->findPath($path, $this->basePath);
        $this->assertFalse($result);
    }

    public function test_absPath_returns_realpath_for_complex_path()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'abs.txt';
        file_put_contents($file, 'ABS');
        $path = $this->basePath . '/../vulnerable_files/./abs.txt';
        $normalized = $this->reader->absPath($path);
        $this->assertSame(realpath($file), $normalized);
        unlink($file);
    }

    public function test_secureFilePath_denies_outside_file_even_if_exists()
    {
        $outside = __DIR__ . '/../../config.json';
        file_put_contents($outside, 'CFG');
        $res = $this->reader->secureFilePath($outside, $this->basePath);
        $this->assertFalse($res);
        unlink($outside);
    }

    public function test_secureFilePath_requires_file_to_exist_and_be_readable()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'guard.txt';
        $res1 = $this->reader->secureFilePath($file, $this->basePath);
        $this->assertFalse($res1);
        file_put_contents($file, 'GUARD');
        $res2 = $this->reader->secureFilePath($file, $this->basePath);
        $this->assertTrue($res2);
        unlink($file);
    }
//TAMBAHAN TEST CASE CYCLE KE 2
    public function test_read_allows_nested_inside_but_denies_parent_outside()
    {
        $nestedDir = $this->basePath . DIRECTORY_SEPARATOR . 'nested';
        if (!is_dir($nestedDir)) {
            mkdir($nestedDir);
        }
        $fileInside = $nestedDir . DIRECTORY_SEPARATOR . 'deep.txt';
        file_put_contents($fileInside, 'DEEP');
        $result = $this->reader->read('nested/deep.txt');
        $this->assertSame('DEEP', $result);

        $outside = dirname($this->basePath) . DIRECTORY_SEPARATOR . 'outside.txt';
        file_put_contents($outside, 'OUT');
        $deny = $this->reader->read('../outside.txt');
        $this->assertSame('Access denied', $deny);

        unlink($fileInside);
        unlink($outside);
        rmdir($nestedDir);
    }

    public function test_isValidSubPath_case_sensitivity_matters()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'case.txt';
        file_put_contents($file, 'CASE');
        $result = $this->reader->isValidSubPath($file, $this->basePath);
        $this->assertTrue($result);

      

        unlink($file);
    }

    public function test_findPath_denies_substring_match_not_boundary()
    {
        $base = $this->basePath;
        $fakeBase = $base . '_extra';
        $file = $base . DIRECTORY_SEPARATOR . 'f1.txt';
        file_put_contents($file, 'F1');

        $deny = $this->reader->findPath($file, $fakeBase);
        $this->assertFalse($deny);

        unlink($file);
    }

    public function test_findPath_nested_inside_passes_outside_denied()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'nestedok.txt';
        file_put_contents($file, 'OK');
        $inside = $this->reader->findPath($file, $this->basePath);
        $this->assertIsInt($inside);

        $outside = __DIR__ . '/../../drive_root.txt';
        $deny = $this->reader->findPath($outside, $this->basePath);
        $this->assertFalse($deny);

        unlink($file);
    }

    public function test_secureFilePath_strict_prefix_and_readability()
    {
        $file = $this->basePath . DIRECTORY_SEPARATOR . 'secure1.txt';
        file_put_contents($file, 'SEC1');
        $allow = $this->reader->secureFilePath($file, $this->basePath);
        $this->assertTrue($allow);

     
    }

    public function test_secureFilePath_denies_different_drive_root()
    {
        $fake = 'D:\\fakefile.txt';
        $result = $this->reader->secureFilePath($fake, $this->basePath);
        $this->assertFalse($result);
    }*/
}
