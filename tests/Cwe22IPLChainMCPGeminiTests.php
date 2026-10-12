<?php


namespace Tests;

use PHPUnit\Framework\TestCase;
use App\VulnFileRead;

class Cwe22IPLChainMCPGeminiTests extends TestCase
{
    private $reader;
    private static $baseDir;
    private static $vulnFilesDir;
    private static $configDir;
    private static $nestedDir;
    private static $caseTestDir;
    private static $strrposTestDir;
    public static function setUpBeforeClass(): void
    {
        // Get path to /src directory
        self::$baseDir = realpath(__DIR__ . '/../src');
        
        // --- Create dummy file structure for tests ---
        self::$vulnFilesDir = self::$baseDir . '/../vulnerable_files';
        self::$configDir = self::$baseDir . '/../config';

        if (!is_dir(self::$vulnFilesDir)) {
            mkdir(self::$vulnFilesDir, 0777, true);
        }
        if (!is_dir(self::$configDir)) {
            mkdir(self::$configDir, 0777, true);
        }
        
        file_put_contents(self::$vulnFilesDir . '/legit.txt', 'hello');
        file_put_contents(self::$configDir . '/settings.ini', 'secret');
        self::$nestedDir = self::$baseDir . '/sub_for_test/src';
        if (!is_dir(self::$nestedDir)) {
             mkdir(self::$nestedDir, 0777, true);
        }
        file_put_contents(self::$nestedDir . '/nested.txt', 'nested data');
        // --- NEW Setup for Mutant 3 (stripos) ---
        self::$caseTestDir = self::$vulnFilesDir . DIRECTORY_SEPARATOR . 'CASE_TEST';
        if (!is_dir(self::$caseTestDir)) {
            mkdir(self::$caseTestDir, 0777, true);
        }
        file_put_contents(self::$caseTestDir . '/case_file.txt', 'case data');

        // --- NEW Setup for Mutants 4 & 5 (strrpos) ---
        // Creates: .../src/a_dir_containing_src/file.txt
        $trickyDirName = 'a_dir_containing_src'; // This string contains 'src'
        self::$strrposTestDir = self::$baseDir . DIRECTORY_SEPARATOR . $trickyDirName;
        if (!is_dir(self::$strrposTestDir)) {
             mkdir(self::$strrposTestDir, 0777, true);
        }
        file_put_contents(self::$strrposTestDir . '/file.txt', 'strrpos data');
    }

    protected function setUp(): void
    {
        // Assuming the class is App\VulnFileRead
        // Adjust namespacing as needed.
        $this->reader = new VulnFileRead(); 
    }

  
    public function testReadValidFileSucceeds(): void
    {
        $content = $this->reader->read('legit.txt');
        $this->assertEquals('hello', $content, 'Should be able to read a valid file inside the base directory');
    }

    
    public function testIsValidSubPathFailsOnNonExistent(): void
    {
        $basePath = self::$baseDir;
        $inputPath = self::$baseDir . '/non_existent_file.txt';
        
        $result = $this->reader->isValidSubPath($inputPath, $basePath);
        $this->assertFalse($result, 'Should return false for non-existent paths');
    }

    public function testIsValidSubPathFailsForOutsidePath(): void
    {
        // Base path is NESTED inside the input path
        $basePath = self::$vulnFilesDir;
        $inputPath = self::$baseDir; // The parent directory
        
        $result = $this->reader->isValidSubPath($inputPath, $basePath);
        $this->assertFalse($result, 'Should return false when input path is a parent of base path');
    }

    public function testFindPathValidReturnsZero(): void
    {
        $basepath = __DIR__;
        $path = __DIR__ . "/legit.txt";
        
        $response = $this->reader->findPath($path, $basepath);
        $this->assertSame(0, $response, 'A valid path should return position 0');
    }

    public function testFindPathFailsForOutsidePath(): void
    {
        $basepath = self::$vulnFilesDir;
        $path = self::$configDir . '/settings.ini'; // Exists, but outside
        
        $response = $this->reader->findPath($path, $basepath);
        $this->assertFalse($response, 'An outside path should return false');
    }

    public function testFindPathFailsOnNonExistent(): void
    {
        $basepath = self::$baseDir;
        $path = self::$baseDir . "/non_existent.txt";
        
        $response = $this->reader->findPath($path, $basepath);
        $this->assertFalse($response, 'A non-existent path should return false');
    }


    public function testAbsPathReturnsEmptyForNonExistent(): void
    {
        $path = __DIR__ . "\\non_existent.txt";
        $response = $this->reader->absPath($path);
        $this->assertEmpty($response, 'absPath of non-existent file should be empty');
    }


    public function testSecureFilePathFailsOnNonExistent(): void
    {
        $basepath = self::$vulnFilesDir;
        $path = self::$vulnFilesDir . '/non_existent.txt';
        
        $response = $this->reader->secureFilePath($path, $basepath);
        $this->assertFalse($response, 'Should return false for non-existent file');
    }

    public function testSecureFilePathFailsOnOutsidePath(): void
    {
        $basepath = self::$vulnFilesDir;
        $path = self::$configDir . '/settings.ini'; // Exists, but outside
        
        $response = $this->reader->secureFilePath($path, $basepath);
        $this->assertFalse($response, 'Should return false for valid file outside base path');
    }

    public function testSecureFilePathFailsOnCaseMismatch(): void
    {
        // We need to create a file in a path that differs only by case.
        $mixedCaseDir = self::$baseDir . '/../src';
     
        $mixedCaseFile = $mixedCaseDir . '/allowed.txt';
        //file_put_contents($mixedCaseFile, 'case test');

        $basepath = self::$vulnFilesDir; // e.g., '.../vulnerable_files'
        $path = $mixedCaseFile;         // e.g., '.../VULNERABLE_files/case.txt'

        $response = $this->reader->secureFilePath($path, $basepath);
        
        $this->assertFalse($response, 'Should fail on case-mismatched path');
    }
    //CHAIN 2

    public function testReadFailsForValidOutsideFile(): void
    {
        // Path goes from /src -> /vulnerable_files -> / -> /config
        $attempt = $this->reader->read('../config/settings.ini');
        $this->assertEquals('Access denied', $attempt, 'Should deny access to valid files outside the base directory');
    }

    
    public function testIsValidSubPathFailsForNonExistentBase(): void
    {
        $inputPath = self::$vulnFilesDir . '/legit.txt';
        $basePath = self::$baseDir . '/non_existent_dir';
        
        $result = $this->reader->isValidSubPath($inputPath, $basePath);
        $this->assertFalse($result, 'Should return false for a non-existent base path');
    }

    
    public function testFindPathFailsForMismatchedCaseBase(): void
    {
        // Only works if the drive letter case is different.
        $basepath = strtolower(self::$vulnFilesDir); // e.g., 'd:\...'
        $path = self::$vulnFilesDir . '/legit.txt';  // realpath() -> 'D:\...'
        
        // Ensure they are actually different before running test
        if (realpath($path) === false || strpos(realpath($path), $basepath) === 0) {
            $this->markTestSkipped('Cannot test case-sensitivity; realpath and lowercase path are identical.');
        }

        $response = $this->reader->findPath($path, $basepath);
        $this->assertFalse($response, 'findPath should be case-sensitive on the base path');
    }

    
    public function testFindPathReturnsZeroForNestedBasePath(): void
    {
        $basepath = self::$baseDir; // '.../src'
        $path = self::$nestedDir . '/nested.txt'; // '.../src/sub_for_test/src/nested.txt'
        
        $response = $this->reader->findPath($path, $basepath);
        $this->assertSame(0, $response, 'findPath should return 0 for nested paths, not the last occurrence');
    }

   
    public function testSecureFilePathFailsForMismatchedCasePath(): void
    {
        $basepath = self::$baseDir; // 'D:\...src'
        $path = strtolower(self::$baseDir) . '/VulnFileRead.php'; // 'd:\...src...'

        if ($path === $basepath . '/VulnFileRead.php') {
             $this->markTestSkipped('Cannot test case-sensitivity; paths are identical.');
        }
        
        $response = $this->reader->secureFilePath($path, $basepath);
        $this->assertFalse($response, 'secureFilePath should be case-sensitive');
    }

    
    public function testSecureFilePathSucceedsForNestedBasePath(): void
    {
        $basepath = self::$baseDir; // '.../src'
        $path = self::$nestedDir . '/nested.txt'; // '.../src/sub_for_test/src/nested.txt'
        
        $response = $this->reader->secureFilePath($path, $basepath);
        $this->assertTrue($response, 'secureFilePath should pass for valid nested path');
    }

    //CHAIN 3
    
    public function testIsValidSubPathFailsOnNonExistentBaseFile(): void
    {
        // A real file
        $inputPath = self::$baseDir . DIRECTORY_SEPARATOR . 'VulnFileRead.php';
        // A non-existent file in the *same* directory
        $basePath = self::$baseDir . DIRECTORY_SEPARATOR . 'non_existent_file.php';

        $result = $this->reader->isValidSubPath($inputPath, $basePath);
        $this->assertFalse($result, 'isValidSubPath should return false if base path does not exist, even if dirname matches');
    }

    public function testFindPathFailsForMismatchedCaseInBasePath(): void
    {
        $path = self::$caseTestDir . DIRECTORY_SEPARATOR . 'case_file.txt';
        $basePath = strtolower(self::$caseTestDir); // Use lowercase path

        // Ensure test is valid (paths are different)
        if (realpath($path) === false || strpos(realpath($path), $basePath) === 0) {
            $this->markTestSkipped('Filesystem is case-insensitive or paths are identical; cannot kill stripos mutant.');
        }

        $response = $this->reader->findPath($path, $basePath);
        $this->assertFalse($response, 'findPath should fail on base path case mismatch');
    }
    
    
    public function testFindPathReturnsFirstOccurrenceOnNestedString(): void
    {
        $path = self::$strrposTestDir . DIRECTORY_SEPARATOR . 'file.txt';
        $basePath = self::$baseDir; // e.g., '.../src'

        $response = $this->reader->findPath($path, $basePath);
        $this->assertSame(0, $response, 'findPath should return pos 0, not the last occurrence');
    }

    public function testSecureFilePathReturnsTrueOnNestedString(): void
    {
        // Must use DIRECTORY_SEPARATOR to avoid mixing \ and /
        $path = self::$strrposTestDir . DIRECTORY_SEPARATOR . 'file.txt';
        $basePath = self::$baseDir; // e.g., '.../src'

        $response = $this->reader->secureFilePath($path, $basePath);
        $this->assertTrue($response, 'secureFilePath should pass for a valid path, even if base string repeats');
    }
}