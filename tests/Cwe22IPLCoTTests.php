<?php

namespace Tests;

use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe22IPLCoTTests extends TestCase
{
    protected VulnFileRead $reader;
    private string $baseDir;
    private string $legitFile;
    private string $outsideFile;
     private $base;
         private static string $vulnerableFilesDir=__DIR__ . '/../config';
    private static string $secretFile= __DIR__ . '/../composer.json';
    protected function setUp(): void
    {
        $this->reader = new VulnFileRead();
        // $this->base = realpath(__DIR__ . '/../vulnerable_files/');
          //$this->basePath = realpath(__DIR__ . '/../vulnerable_files/');
           $this->baseDir = realpath(__DIR__ . '/../vulnerable_files/');
        $this->legitFile = 'legit.txt';
        $this->outsideFile = '../config.ini'; // or any file outside baseDir
        // Ensure test directory exists
        
    }
//ZERO CoT SHOT GPT TEST CASE GENERATED 7 TC 
/** -------- Category 1: Realpath substitution mutants -------- */
  /*  public function testRejectsTraversalPath()
    {
        $result = $this->reader->read('../../config.ini');
        $this->assertSame('Access denied', $result, "Must deny traversal attempts");
    }

    public function testLegitFileCanBeRead()
    {
        $result = $this->reader->read('legit.txt');
        $this->assertStringContainsString('content', $result);
    }

    public function testDisallowOutsidePayloadFile()
    {
        $result = $this->reader->read('..\..\..\config.ini');
        $this->assertSame('Access denied', $result, "Must not allow config.ini payloads");
    }

       public function testDoesNotAcceptFilesOutsideBaseDrive()
    {
        $fake = __DIR__ . '/../another_dir/fake.txt';
        $result = $this->reader->read($fake);
        $this->assertSame('Access denied', $result);
    }

   
    public function testFindPathMatchesOnlyAtStart()
    {
        $path = $this->baseDir . '/legit.txt';

        // Must return 0 if starts with base
        $this->assertSame(0, $this->reader->findPath($path, $this->baseDir));

        // If base appears later, must NOT return 0
        $malicious = '/var/tmp' . $this->baseDir;
        $this->assertNotSame(0, $this->reader->findPath($malicious, $this->baseDir));
    }

   
    public function testIsValidSubPathReturnsFalseOnInvalid()
    {
        $fake = '/etc/passwd'; // outside base
        $this->assertFalse($this->reader->isValidSubPath($fake, $this->baseDir));
    }

   
    public function testSecureFilePathMustCheckExistence()
    {
        $nonExistent = $this->baseDir . '/not_here.txt';
        $this->assertFalse(
            $this->reader->secureFilePath($nonExistent, $this->baseDir),
            "Must reject non-existent files"
        );
    }
   */

  /*  //QWEN 7 TC 3adjust
    public function testPathTraversalBlocked(): void
{
    // Valid file
    $this->assertEquals('safecontent', $this->reader->read('allowed.txt'));

    // Traversal attempts
    $traversalPaths = [
        '../composer.json', // parent dir
        '../../composer.json',
        '..\\..\\composer.json', // Windows style
        '../../../etc/passwd',
        '..%2f..%2fcomposer.json', // URL-encoded
        'safe.txt/../../composer.json',
        '/etc/passwd',
        'C:\\Windows\\system.ini',
        __DIR__ . '/../../composer.json'
    ];

    foreach ($traversalPaths as $path) {
        $this->assertEquals('Access denied', $this->reader->read($path));
    }
}
public function testBasePathValidationStrict(): void
{
    // Create a file just outside base dir
    $outsideFile = __DIR__ . '/../outside.txt';
    file_put_contents($outsideFile, 'should not be readable');

    // Even if realpath resolves it, it must be under base
    $this->assertEquals('Access denied', $this->reader->read('../outside.txt'));

    // Clean up
    unlink($outsideFile);
}
public function testSecurityCheckNotBypassed(): void
{
    // Create a readable file outside base
    $dangerousFile = sys_get_temp_dir() . '/danger.txt';
    file_put_contents($dangerousFile, 'danger');

    // Even though it exists and is readable, it's outside base → must be denied
    // Simulate direct call to secureFilePath if needed
    $basePath = realpath(__DIR__ . '/../vulnerable_files');
    $this->assertFalse($this->reader->secureFilePath($dangerousFile, $basePath));

    unlink($dangerousFile);
}
public function testPathPrefixCheckIsStrict(): void
{
    $basePath = __DIR__;
    $validPath = __DIR__.'/legit.txt'; // starts with base
    $invalidPath = __DIR__ . '/../configs'; // contains base but not prefix

    // Only validPath should pass
    $this->assertTrue($this->reader->secureFilePath($validPath, $basePath));
    $this->assertFalse($this->reader->secureFilePath($invalidPath, $basePath));
}
public function testAlwaysTrueMutantsKilled(): void
{
    // This should never be allowed
    $result = $this->reader->read('../../../etc/passwd');
    $this->assertEquals('Access denied', $result);
}

public function testNormalOperationUnaffected(): void
{
    // If mutants hardcode a path, safe.txt won't be readable
    $this->assertSame( "safecontent",$this->reader->read('allowed.txt'));
}
public function testSystemFilesNotAccessible(): void
{
    $systemFiles = [
        'C:\\Windows\\win.ini',
        'D:\\pagefile.sys',
        '/etc/passwd' // for Unix-like systems
    ];

    foreach ($systemFiles as $file) {
        if (file_exists($file)) {
            // Try to trick the system into reading it
            $filename = str_replace(realpath(__DIR__ . '/../vulnerable_files') . DIRECTORY_SEPARATOR, '', $file);
            // But better: use traversal that resolves to it
            $this->assertEquals('Access denied', $this->reader->read('../../../Windows/win.ini'));
            return;
        }
    }

    // If no system file exists, at least ensure base restriction holds
    $this->assertEquals('Access denied', $this->reader->read('../composer.json'));
}*/
//GEMINI 2.5 Pro 2adjusted
public function testitShouldDenyAccessForPathTraversalPayloads(): void
    {
        // Payload attempts to go up one directory from 'test_vulnerable_files' to access sensitive_file.txt
        $maliciousFilename = '../sensitive_file.txt';
        $result = $this->reader->read($maliciousFilename);
        $this->assertEquals('Access denied', $result, "Failed to block path traversal payload.");
    }

    public function testitShouldDenyAccessForNonExistentFile(): void
    {
        $result = $this->reader->read('nonexistent.txt');
        $this->assertEquals('Access denied', $result, "Failed to block access to a non-existent file.");
    }
    
    public function testitShouldReturnTheCorrectContentForAValidFile(): void
    {
        $content = $this->reader->read('allowed.txt');
        $this->assertEquals('safecontent', $content, "Did not return the expected content for safe.txt.");
    }
  
    public function testitShouldBlockAccessToFilesOutsideTheBaseDirectory(): void
    {
        $absolutePathToSensitiveFile = realpath(__DIR__ . '/../composer.json');
        // This simulates an attacker providing a full path, which should be blocked.
        $result = $this->reader->read($absolutePathToSensitiveFile);
        $this->assertEquals('Access denied', $result, "Allowed access to an absolute path outside the base directory.");
    }
  
    public function testfindPathShouldReturnFalseIfBasePathIsNotAPrefix(): void
    {
        $basePath = realpath($this->baseDir);
        // A tricky path where the base path name appears, but not at the start.
        $trickyPath = realpath(__DIR__ . '/..') . '/some_decoy_dir' . $basePath . '/safe.txt';

        // We use is_bool and assertFalse because strpos can return 0, which is a valid success case.
        $result = $this->reader->findPath($trickyPath, $basePath);
        $this->assertIsBool($result, "Expected boolean false for non-prefixed path.");
        $this->assertFalse($result, "findPath incorrectly validated a non-prefixed path.");
    }
   
    public function testfindPathShouldReturnFalseForUnrelatedPaths(): void
    {
        $basePath = realpath($this->baseDir);
        $unrelatedPath = realpath(__DIR__ . '/..'); // Some other valid directory on the system

        $result = $this->reader->findPath($unrelatedPath, $basePath);
        $this->assertIsBool($result);
        $this->assertFalse($result, "findPath incorrectly validated a completely unrelated path.");
    }
   
    public function testsecureFilePathShouldReturnFalseForTraversalPaths(): void
    {
        $basePath = realpath($this->baseDir);
        $filePath = $basePath . '/../sensitive_file.txt';
        
        $this->assertFalse($this->reader->secureFilePath($filePath, $basePath), "secureFilePath failed to block a traversal path.");
    }

    public function testsecureFilePathShouldReturnFalseForNonExistentPaths(): void
    {
        $basePath = realpath($this->baseDir);
        $filePath = $basePath . '/nonexistent.txt';
        $this->assertFalse($this->reader->secureFilePath($filePath, $basePath), "secureFilePath failed to block a non-existent file path.");
    }
     /*   //Claude Sonnet 4.5 23 TC 14 adjusted
        public function testRealpathNotReplacedByBasename()
    {
        // basename() returns only the filename, not the full path
        // This should fail when realpath is replaced with basename
        $result = $this->reader->read('allowed.txt');
        $this->assertNotEquals('Access denied', $result);
        
        // Try traversal - should be denied
        $result = $this->reader->read('../../../etc/passwd');
        $this->assertEquals('Access denied', $result);
        
        // Verify the check uses full path comparison
        $result = $this->reader->read('../../config.php');
        $this->assertEquals('Access denied', $result);
    }

    
    public function testRealpathNotReplacedByDirname()
    {
        // dirname() returns parent directory, not the resolved path
        // Create a path that would pass with dirname but fail with realpath
        $result = $this->reader->read('subdir/../allowed.txt');
        
        // If realpath is replaced by dirname, the path check will fail
        $this->assertNotEquals('Access denied', $result, 
            'dirname() replacement would break path resolution');
    }

  
    public function testRealpathNotReplacedByPathinfo()
    {
        // pathinfo() with PATHINFO_DIRNAME doesn't resolve symlinks or .. sequences
        $result = $this->reader->read('./allowed.txt');
        $this->assertNotEquals('Access denied', $result);
        
        // Test with path containing . and ..
        $result = $this->reader->read('./subdir/../allowed.txt');
        $this->assertNotEquals('Access denied', $result);
    }

 
    public function testHardcodedAbsolutePathRejected()
    {
        $result = $this->reader->read('legitimate.txt');
        
        // Verify the result depends on the actual input, not a hardcoded path
        $this->assertIsString($result);
        $this->assertNotEmpty($result);
        
        // Multiple reads should be consistent with input
        $result1 = $this->reader->read('file1.txt');
        $result2 = $this->reader->read('allowed.txt');
        
        // If hardcoded, both would return the same file content
        $this->assertNotEquals($result1, $result2, 
            'Results should differ based on input, not hardcoded path');
    }

   
    public function testConfigIniTraversalBlocked()
    {
        $result = $this->reader->read('..\..\..\..\config.ini');
        $this->assertEquals('Access denied', $result);
        
        $result = $this->reader->read('../../../config.ini');
        $this->assertEquals('Access denied', $result);
    }

   
    public function testFilesTraversalBlocked()
    {
        $result = $this->reader->read('..\..\..\..\files.txt');
        $this->assertEquals('Access denied', $result);
        
        $result = $this->reader->read('../../../../files.txt');
        $this->assertEquals('Access denied', $result);
    }

    public function testCurrentDirectoryNotHardcoded()
    {
        // If path is hardcoded to '\legit.txt', it won't find files in the correct directory
        $result = $this->reader->read('allowed.txt');
        $this->assertNotEquals('Access denied', $result);
    }

   
    public function testDriveLetterNotAcceptedAsBase()
    {
        // If str_starts_with checks against 'C:\' or 'D:\', any file on that drive would pass
        // This is a major security flaw
        
        // Legitimate file should work
        $result = $this->reader->read('allowed.txt');
        $this->assertNotEquals('Access denied', $result);
        
        // Traversal should still be blocked
        $result = $this->reader->read('../../../windows/system32/config/sam');
        $this->assertEquals('Access denied', $result);
        
        // Test absolute path outside base
        if (DIRECTORY_SEPARATOR === '\\') {
            $result = $this->reader->read('C:\\Windows\\System32\\drivers\\etc\\hosts');
            $this->assertEquals('Access denied', $result);
        }
    }

 
    public function testIsValidSubPathNotAlwaysTrue()
    {
        // Test that invalid paths return false, not always true
        $basePath = __DIR__ ;
        
        
        $result = $this->reader->isValidSubPath(__DIR__.'../config/', $basePath);
        $this->assertFalse($result, 'Invalid path should return false, not true');
        
        // Valid path should return true
        $validPath = $basePath . '/legit.txt';
        $result = $this->reader->isValidSubPath($validPath, $basePath);
        $this->assertTrue($result);
        
        // Non-existent path
        $result = $this->reader->isValidSubPath('/nonexistent/path', $basePath);
        $this->assertFalse($result);
    }

    public function testFindPathUsesRealpath()
    {
        $basePath = __DIR__;
        $validFile = $basePath . '/legit.txt';
        
        // findPath should return 0 (found at position 0) for valid subpath
        $result = $this->reader->findPath($validFile, $basePath);
        $this->assertEquals(0, $result);
        
        // Invalid path
        $invalidFile = dirname($basePath) . '/outside.txt';
        $result = $this->reader->findPath($invalidFile, $basePath);
        $this->assertFalse( $result);
    }

  
    public function testPathCheckingIsCaseSensitive()
    {
        $basePath = __DIR__;

        
        // On Unix, paths are case-sensitive
        $validFile = $basePath . '/legit.txt';
        $result = $this->reader->findPath($validFile, $basePath);
        $this->assertIsInt($result);
    }

   
    public function testStrposNotReplacedByStrContains()
    {
        $basePath = __DIR__;
        
        // strpos returns position (0 for match at start)
        // str_contains returns boolean
        // This difference should be detected
        
        $validFile = $basePath . '/legit.txt';
        $result = $this->reader->findPath($validFile, $basePath);
        $this->assertIsInt($result, 'findPath should return int, not bool');
        $this->assertEquals(0, $result);
    }

 
    public function testStrposNotReplacedByStrStartsWith()
    {
        $basePath = __DIR__;
        $validFile = $basePath . '/legit.txt';
        
        // strpos returns int position, str_starts_with returns bool
        $result = $this->reader->findPath($validFile, $basePath);
        $this->assertIsInt($result);
    }

  
    public function testStrposNotReplacedByStrrpos()
    {
        $basePath = __DIR__;
        
        // Create path where basePath appears multiple times
        // strrpos finds last occurrence, not first
        $pathWithRepeatedBase = $basePath . '/' . basename($basePath) . '/file.txt';
        
        $result = $this->reader->findPath($basePath . '/legit.txt', $basePath);
        $this->assertEquals(0, $result, 'Should find at position 0');
    }

  
    public function testStrposNotReplacedByStrstrOrStrpbrk()
    {
        $basePath = __DIR__;
        $validFile = $basePath . '/legit.txt';
        
        // strstr returns string, strpbrk returns string, strpos returns int
        $result = $this->reader->findPath($validFile, $basePath);
        $this->assertIsInt($result, 'findPath must return int, not string');
    }

    
    public function testFindPathNotAlwaysZero()
    {
        $basePath = __DIR__;
        
        // Invalid path should NOT return 0
        $invalidPath = $basePath . '/../config.ini' ;
        $result = $this->reader->findPath($invalidPath, $basePath);
        $this->assertFalse( $result, 'Invalid path should not return 0');
        
        // Valid path should return 0
        $validPath = $basePath . '/legit.txt';
        $result = $this->reader->findPath($validPath, $basePath);
        $this->assertEquals(0, $result);
    }

    
    public function testFindPathNotAlwaysTrue()
    {
        $basePath = __DIR__;
        
        // findPath returns int|false, not boolean true
        $result = $this->reader->findPath($basePath . '/legit.txt', $basePath);
        $this->assertIsNotBool($result, 'findPath should return int or false, not true');
    }

    public function testAbsPathUsesRealpath()
    {
        // Test with relative path containing ..
        $testPath = __DIR__ . '/legit.txt';
        
        if (file_exists($testPath)) {
            $result = $this->reader->absPath($testPath);
            
            // realpath resolves .., basename/dirname don't
            // Result should be normalized without ..
            $this->assertStringNotContainsString('..', $result);
            $this->assertStringNotContainsString('subdir', $result);
        }
        
        // Test that absolute path is properly normalized
        $absolutePath = __DIR__ . '/legit.txt';
        if (file_exists($absolutePath)) {
            $result = $this->reader->absPath($absolutePath);
            $this->assertNotEmpty($result);
            $this->assertIsString($result);
        }
    }

  
    public function testPathValidationRequired()
    {
        // If path validation is removed, any file would pass
        $testPath = '/etc/passwd';
        $basePath = __DIR__;
        
        $result = $this->reader->secureFilePath($testPath, $basePath);
        $this->assertFalse($result, 'Path outside base should be rejected');
        
        // Valid path should pass
        $validPath = $basePath . '/legit.txt';
        if (file_exists($validPath)) {
            $result = $this->reader->secureFilePath($validPath, $basePath);
            $this->assertTrue($result);
        }
    }


    public function testFileExistenceCheckRequired()
    {
        $basePath = __DIR__;
        
        // Non-existent file within base should be rejected
        $nonExistentFile = $basePath . '/nonexistent_file_12345.txt';
        $result = $this->reader->secureFilePath($nonExistentFile, $basePath);
        $this->assertFalse($result, 'Non-existent file should return false');
        
        // Existing file should pass
        $existingFile = $basePath . '/legit.txt';
        if (file_exists($existingFile)) {
            $result = $this->reader->secureFilePath($existingFile, $basePath);
            $this->assertTrue($result);
        }
    }


    public function testComprehensiveTraversalAttacks()
    {
        $attacks = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            'legitimate.txt/../../../etc/passwd',
            './../../etc/shadow',
            'subdir/../../../../../../etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//....//etc/passwd',
        ];
        
        foreach ($attacks as $attack) {
            $result = $this->reader->read($attack);
            $this->assertEquals('Access denied', $result, 
                "Attack vector '$attack' should be blocked");
        }
    }


    public function testLegitimateAccessAllowed()
    {
        $legitimatePaths = [
            'unreadable_test.txt','unreadable_files.txt',
            'fileB.txt'
        ];
        
        foreach ($legitimatePaths as $path) {
            $fullPath = __DIR__ . DIRECTORY_SEPARATOR . $path;
            if (file_exists($fullPath)) {
                $result = $this->reader->read($path);
                $this->assertNotEquals('Access denied', $result,
                    "Legitimate path '$path' should be allowed");
            }
        }
    }

    
    public function testEdgeCases()
    {
        $result = $this->reader->read('legits.txt');        
        $this->assertEquals('Access denied', $result);
        $result = $this->reader->secureFilePath('', __DIR__);
        $this->assertFalse($result);
        
        $result = $this->reader->secureFilePath(null, __DIR__);
        $this->assertFalse($result);
    }*/
}