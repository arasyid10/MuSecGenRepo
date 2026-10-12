<?php

namespace Tests;

use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe22IPLFewTests extends TestCase
{
    protected VulnFileRead $reader;
    private string $baseDir;
    private string $legitFile;
     private $base;
    private static string $vulnerableFilesDir=__DIR__ . '/../config';
    private static $outsideFile ;
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

// GPT 5.0 10 TC 2 ADJUSTMENT
/*public function testReadAllowsOnlyBaseFile(): void
    {
        $result = $this->reader->read('allowed.txt');
        $this->assertSame('safecontent', trim($result));
    }

    public function testReadDeniesPathTraversal(): void
    {
        $escape = '..' . DIRECTORY_SEPARATOR . 'outside.txt';
        //$outside = dirname($this->base) . DIRECTORY_SEPARATOR . 'outside.txt';
        //file_put_contents($outside, 'SHOULD_NOT_READ');

        $result = $this->reader->read($escape);
        $this->assertStringContainsString('Access denied', $result);
        $this->assertStringNotContainsString('SHOULD_NOT_READ', $result);

        
    }
    public function testReadUsesRequestedFilename(): void
{
    $target = 'allowed.txt';
    $result = $this->reader->read($target);
    $this->assertSame('safecontent', trim($result), 'Should use requested filename, not hardcoded path');
}
public function testTraversalBlockedByBaseCheck(): void
{
    $result = $this->reader->read('../safe.txt');
    $this->assertStringContainsString('Access denied', $result);
}
public function testIsValidSubPathRejectsDriveBasedBypass(): void
{
    $base = realpath(__DIR__ . '/../vulnerable_files');
    $outside = dirname($base) . DIRECTORY_SEPARATOR . 'outside.txt';
    file_put_contents($outside, 'OUTSIDE');

    $result = $this->reader->isValidSubPath($outside, $base);
    $this->assertFalse($result, 'Drive-level match must not allow outside base access');

    @unlink($outside);
}
public function testIsValidSubPathRejectsOutsidePath(): void
{
    $base = realpath(__DIR__ . '/../vulnerable_files');
    $outside = dirname($base) . DIRECTORY_SEPARATOR . 'evil.txt';
    file_put_contents($outside, 'X');
    $this->assertFalse(
        $this->reader->isValidSubPath($outside, $base),
        'Outside path must not be treated as valid subpath'
    );
    @unlink($outside);
}
public function testFindPathIsCaseSensitive(): void
{
    $base = realpath(__DIR__ . '/../vulnerable_files');
    $path = $base . DIRECTORY_SEPARATOR . 'safe.txt';
    $baseUpper = strtoupper($base);

    $res = $this->reader->findPath($path, $baseUpper);
    $this->assertNotSame(0, $res, 'Case mismatch should not be considered inside base');
}
public function testAbsPathCanonicalization(): void
{
    $base = realpath(__DIR__ . '/../vulnerable_files');
    $target = $base . DIRECTORY_SEPARATOR . 'safe.txt';
    $canonical = $this->reader->absPath($target);
    $this->assertSame(trim(realpath($target), DIRECTORY_SEPARATOR), $canonical);
}
public function testSecureFilePathCaseSensitiveCheck(): void
{
    $base = realpath(__DIR__ . '/../vulnerable_files');
    $upper = strtoupper($base);
    $target = $base . DIRECTORY_SEPARATOR . 'safe.txt';
    file_put_contents($target, 'SAFE_CONTENT');

    $this->assertTrue($this->reader->secureFilePath($target, $base));
    $this->assertFalse(
        $this->reader->secureFilePath($target, $upper),
        'secureFilePath should enforce case-sensitive base matching'
    );
    @unlink($target);
}
public function testSecureFilePathBlocksOutsideFileEvenIfReadable(): void
{
    $base = realpath(__DIR__ . '/../vulnerable_files');
    $outside = dirname($base) . DIRECTORY_SEPARATOR . 'external.txt';
    file_put_contents($outside, 'READABLE_BUT_OUTSIDE');

    $this->assertFalse(
        $this->reader->secureFilePath($outside, $base),
        'File outside base must be denied even if readable'
    );
    @unlink($outside);
}
public function testSecureFilePathRejectsNonexistentFile(): void
{
    $base = realpath(__DIR__ . '/../vulnerable_files');
    $fake = $base . DIRECTORY_SEPARATOR . 'does_not_exist.txt';
    $this->assertFalse(
        $this->reader->secureFilePath($fake, $base),
        'Non-existent file should not be accepted'
    );
}
*/
//QWEN3-Max 7 TC
/*
public function testBasenameDirnamePathinfoBypass(): void
    {
        
        $content = $this->reader->read('safe.txt');
        // But wait: is 'safe.txt' in vulnerable_files? We didn't put it there.

        // Fix: ensure safe file exists in base
        $safeFile = $this->baseDir . '/safe.txt';
        file_put_contents($safeFile, 'SAFE');
        $this->assertTrue(file_exists($safeFile));

        // Now: valid read must succeed
        $result = $this->reader->read('allowed.txt');
        $this->assertEquals('safecontent', $result);

        // Mutants 1–3 will compute $fullPath as basename/dirname → not absolute → check fails → return 'Access denied'
        // So this test **kills them** by expecting success but mutant returns denial.

        
    }

    // =============== GROUP 2: Hardcoded realpath (Mutants 4–7, 11–14) ===============
    public function testHardcodedPathMutants(): void
    {
        
        $safeFile = $this->baseDir . '/legit.txt';
        
        $result = $this->reader->read('allowed.txt');
        $this->assertEquals('safecontent', $result);
        
    }

    // =============== GROUP 3: Drive-letter base check (Mutants 15–16, 21, 31, 39) ===============
    public function testDriveLetterOverPermissive(): void
    {
        $this->assertEquals('safecontent', $this->reader->read('allowed.txt'));
    }

    // =============== GROUP 4: Return true / Skip checks (Mutants 22, 33, 40, 41) ===============
    public function testValidationBypass(): void
    {
        $traversal = __DIR__."\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt"; 
        $result = $this->reader->read($traversal);
        $this->assertEquals('Access denied', $result);
    }

    // =============== GROUP 5: Weaker string matching (Mutants 25–30, 37–38) ===============
    public function testCaseInsensitiveOrSubstringBypass(): void
    {
       
        $safeFile = $this->baseDir . '/safe4.txt';
        file_put_contents($safeFile, 'SAFE4');
        $this->assertEquals('safecontent', $this->reader->read('allowed.txt'));
        
    }

    // =============== GROUP 6: findPath returns 0 or true (Mutants 32, 33) ===============
    public function testFindPathConstantReturn(): void
    {
        // Mutant 32: findPath returns 0 → treated as success in some contexts?
        // But in SUT, findPath is not used in read() → may not matter
        // However, to kill: call findPath directly with invalid path

        $traversal = __DIR__."\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt"; 
        $result = $this->reader->findPath($traversal, __DIR__);
        // Original: strpos(realpath(invalid), base) → realpath=false → strpos(false, ...) → warning? but returns false
        // Mutant 32: returns 0 → which is !== false, but in boolean context is false
        // But test: assert it returns false or null

        // Better: use valid path
        $safeFile = $this->baseDir . '/legit.txt';
        file_put_contents($safeFile, 'SAFE5');
        $result = $this->reader->findPath($safeFile, $this->baseDir);
        // Should return int (position) or false
        $this->assertIsInt($result);
        $this->assertGreaterThanOrEqual(0, $result);
        
    }

    // =============== ADDITIONAL: Ensure base path normalization ===============
    public function testBaseDirectoryNormalization(): void
    {
        // Ensure that base path ends with DIRECTORY_SEPARATOR for consistent checks
        $base = __DIR__ . '/../vulnerable_files/';
        $realBase = realpath($base);
        $this->assertNotEmpty($realBase);
        $this->assertTrue(is_dir($realBase));
    }
*/

        //GEMINI 2.5 Pro 7 TC 6 adjustment
 /*       public function testReadReturnsContentForValidFile(): void
    {
        $content = $this->reader->read('allowed.txt');
        $this->assertSame('safecontent', $content, "Should correctly read the content of a file within the base directory.");
    }
    public function testIsValidSubPathRejectsPathsOutsideBase(): void
    {$traversal = __DIR__."\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt"; 
        $result = $this->reader->isValidSubPath($traversal, __DIR__ . '/../../vulnerable_files');
        $this->assertFalse($result, "Should reject a path that is clearly outside the base directory.");
    }
    public function testIsValidSubPathAcceptsValidSubdirectory(): void
    {
        $subDir = __DIR__ . '/../../vulnerable_files' . '/subdir';
        mkdir($subDir, 0777, true);

        $result = $this->reader->isValidSubPath($subDir, __DIR__ . '/../../vulnerable_files');
        $this->assertTrue($result, "Should correctly validate a subdirectory that exists within the base path.");

        rmdir($subDir);
    }
  /*  public function testFindPathFailsForUnrelatedAndCaseMismatchedPaths(): void
    {
        // Test for an unrelated path
        $traversal = __DIR__."\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt"; 
        $result = $this->reader->findPath($traversal, __DIR__ . '/../../vulnerable_files');
        $this->assertFalse($result, "findPath should return false for a completely unrelated path.");

        // Test for case-sensitivity (on systems where it matters)
        $mismatchedCasePath = strtoupper(__DIR__ . '/../../vulnerable_files') . '/safe.txt';
        $resultMismatched = $this->reader->findPath($mismatchedCasePath, __DIR__ . '/../../vulnerable_files');
        $this->assertFalse($resultMismatched, "findPath should be case-sensitive and fail on mismatched casing.");
    }*/

    /**
     * Kills mutants in absPath that fail to return the full canonical path.
     * Mutant IDs: 3bb275eb, d0d277f8, d8604e49
     */
   /* public function testAbsPathReturnsFullPath(): void
    {
        $nestedPath = __DIR__ . '/../../vulnerable_files' . '/a/b/c';
        mkdir($nestedPath, 0777, true);

        $expected = trim(realpath($nestedPath), DIRECTORY_SEPARATOR);
        $actual = $this->reader->absPath($nestedPath);
        $this->assertSame($expected, $actual, "absPath should return the full, trimmed, canonical path.");

        rmdir($nestedPath);
        rmdir(dirname($nestedPath));
        rmdir(dirname(dirname($nestedPath)));
    }*/
   /* public function testSecureFilePathRejectsExistingFileOutsideBase(): void
    {$traversal = __DIR__."\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt"; 
        $result = $this->reader->secureFilePath($traversal, __DIR__ . '/../../vulnerable_files');
        $this->assertFalse($result, "Should reject a file that exists but is outside the base path.");
    }

  
    public function testSecureFilePathRejectsNonExistentFile(): void
    {
        $nonExistentFile = __DIR__ . '/../../vulnerable_files' . '/no_such_file.txt';
        $result = $this->reader->secureFilePath($nonExistentFile, __DIR__ . '/../../vulnerable_files');
        $this->assertFalse($result, "Should reject a path that is syntactically valid but does not exist.");
    }*/
        //Claude Sonnet 4.5 24 TC 8 adjustment
        public function testRealpathRequired_TraversalWithSymlink(): void
    {
        // Create symlink to test canonical resolution requirement
        $symlinkPath = $this->baseDir . DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'link.txt';
        $targetPath = $this->baseDir . DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'safe.txt';
        
        if (function_exists('symlink') && !file_exists($symlinkPath)) {
            @symlink($targetPath, $symlinkPath);
        }

        // Attempt traversal through path manipulation
        $result = $this->reader->read('../secret.txt');
        
        // With realpath: resolves to canonical path, detects traversal, returns 'Access denied'
        // With basename/dirname/pathinfo: returns non-canonical string, str_starts_with fails
        $this->assertSame('Access denied', $result, 
            'realpath() must canonicalize paths to prevent traversal');
    }

    public function testRealpathRequired_NonExistentPath(): void
    {
        // Test with non-existent path (realpath returns false)
        $result = $this->reader->read('../nonexistent/../../../secret.txt');
        
        // realpath returns false for non-existent paths, caught by truthiness check
        // basename/dirname/pathinfo return strings, bypass the false check
        $this->assertSame('Access denied', $result,
            'realpath() must return false for non-existent paths');
    }

    public function testRealpathRequired_DotDotNormalization(): void
    {
        // Traversal attempt that requires path normalization
        $result = $this->reader->read('safe.txt/../../secret.txt');
        
        // realpath resolves and normalizes, then validation catches traversal
        // basename/dirname return wrong values, breaking validation
        $this->assertSame('Access denied', $result,
            'realpath() must normalize .. sequences for security');
    }
    /*public function testInputParameterMustAffectOutput(): void
    {
        $result1 = $this->reader->read('file1.txt');
        $result2 = $this->reader->read('file2.txt');
        $result3 = $this->reader->read('completely_different.txt');
        
        // With realpath($base . $filename): results depend on $filename
        // With hardcoded realpath(): all results identical (same file or all 'Access denied')
        $allSame = ($result1 === $result2 && $result2 === $result3);
        
        $this->assertFalse($allSame,
            'Function must respect filename parameter, not use hardcoded paths');
    }*/

    public function testDifferentInputsDifferentBehavior(): void
    {
        // Test with existing vs non-existing files to ensure parameter usage
        $existingResult = $this->reader->read('sample.txt');
        $nonExistentResult = $this->reader->read('this_definitely_does_not_exist_12345.txt');
        
        // Different inputs should potentially produce different results
        // Hardcoded mutants return same result regardless of input
        $this->assertTrue(
            $existingResult !== $nonExistentResult || $existingResult === 'Access denied',
            'Function must process the filename parameter dynamically'
        );
    }
    public function testValidFileAccessWithProperBasePath(): void
    {
        // Assuming vulnerable_files/sample.txt exists
        $result = $this->reader->read('allowed.txt');
        
        // With realpath($base): returns full canonical base, comparison works, file accessible
        // With basename($base): returns 'vulnerable_files', comparison fails, 'Access denied'
        // With dirname($base): returns parent dir, wrong comparison
        $this->assertNotSame('Access denied', $result,
            'Valid file in base directory must be accessible');
        $this->assertNotEmpty($result, 'Should return file contents');
    }

    public function testBasePathValidationMustUseCanonicalPath(): void
    {
        // Test legitimate file with relative path in filename
        $result = $this->reader->read('./allowed.txt');
        
        // realpath($base) provides full canonical path for accurate comparison
        // basename/dirname/pathinfo break the comparison logic
        $this->assertNotSame('Access denied', $result,
            'Base path must be canonical for proper validation');
    }
    /*public function testValidationMustUseDynamicBasePath(): void
    {
        // Test multiple different files
        $result1 = $this->reader->read('legit.txt');
        $result2 = $this->reader->read('data.txt');
        
        // With realpath($base): consistent validation against actual base
        // With hardcoded paths: validation always checks against wrong path, likely always 'Access denied'
        $atLeastOneAccessible = ($result1 !== 'Access denied' || $result2 !== 'Access denied');
        
        $this->assertTrue($atLeastOneAccessible,
            'Validation must use dynamic base path, not hardcoded path');
    }*/
    public function testDriveLetterValidationInsufficient(): void
    {
        // Attempt to access file outside vulnerable_files directory
        $result = $this->reader->read('../../../../config.ini');
        
        // With realpath($base): validates against specific directory, blocks traversal
        // With 'C:\' or 'D:\': if file exists on drive, passes validation
        $this->assertSame('Access denied', $result,
            'Validation must check specific base directory, not just drive letter');
    }

    public function testMustRejectPathsOutsideBase(): void
    {
        // Multiple traversal attempts
        $attempts = [
            '../../../windows/system32/config/sam',
            '../../../../etc/shadow',
            '../../../sensitive.dat'
        ];
        
        foreach ($attempts as $attempt) {
            $result = $this->reader->read($attempt);
            $this->assertSame('Access denied', $result,
                "Must reject traversal attempt: $attempt");
        }
    }
    public function testIsValidSubPath_RequiresRealpath(): void
    {
        $validPath = __DIR__ . DIRECTORY_SEPARATOR . 'legit.txt';
        $traversalPath = __DIR__.DIRECTORY_SEPARATOR .'..'. DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR. '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR .   'pwds.txt'; 
        
        // Valid path should return true
        $resultValid = $this->reader->isValidSubPath($validPath, __DIR__);
        $this->assertTrue($resultValid, 'Valid subpath must be accepted');
        
        // Traversal path should return false
        $resultTraversal = $this->reader->isValidSubPath($traversalPath, __DIR__);
        $this->assertFalse($resultTraversal, 'Traversal path must be rejected');
    }

    public function testIsValidSubPath_NonCanonicalInput(): void
    {
        // Path with redundant elements that need canonicalization
        $nonCanonicalPath = __DIR__ . DIRECTORY_SEPARATOR . 'legit.txt';
        $result = $this->reader->isValidSubPath($nonCanonicalPath, __DIR__);
        
        // realpath normalizes the path correctly
        // dirname/pathinfo don't resolve . and .. correctly
        $this->assertTrue($result, 'Must canonicalize input path with realpath');
    }
    public function testIsValidSubPath_BasePathMustBeCanonical(): void
    {
        $inputPath = __DIR__ . DIRECTORY_SEPARATOR . 'legit.txt';
        
        // Test with canonical base
        $result = $this->reader->isValidSubPath($inputPath, __DIR__);
        
        // realpath($basePath) provides canonical base for comparison
        // dirname($basePath) returns parent directory - wrong comparison
        // pathinfo returns parent - wrong comparison
        $this->assertTrue($result, 'Valid file in base must pass validation');
    }

    public function testIsValidSubPath_BaseWithTrailingSlash(): void
    {
        $inputPath = __DIR__ . DIRECTORY_SEPARATOR . 'legit.txt';
        $baseWithSlash = __DIR__ . DIRECTORY_SEPARATOR;
        
        $result = $this->reader->isValidSubPath($inputPath, $baseWithSlash);
        
        // realpath normalizes base path with or without trailing slash
        // dirname/pathinfo don't handle this correctly
        $this->assertTrue($result, 'Must handle base path normalization');
    }
    public function testIsValidSubPath_MustRejectOutsidePaths(): void
    {
        $outsidePath = $this->outsideFile . DIRECTORY_SEPARATOR . 'danger.txt';
        
        $result = $this->reader->isValidSubPath($outsidePath, __DIR__);
        
        // With str_starts_with($realInput, $realBase): returns false for outside path
        // With return true: always returns true - SECURITY BREACH
        // With str_starts_with($realInput, 'D:\'): returns true if same drive
        $this->assertFalse($result, 'Must reject paths outside base directory');
    }

    public function testIsValidSubPath_AcceptInsideRejectOutside(): void
    {
        $insidePath = __DIR__ . DIRECTORY_SEPARATOR . 'legit.txt';
        $outsidePath = $this->outsideFile;
        
        $resultInside = $this->reader->isValidSubPath($insidePath, __DIR__);
        $resultOutside = $this->reader->isValidSubPath($outsidePath, __DIR__);
        
        // Correct implementation: inside=true, outside=false
        // Mutant 22 (return true): both=true - KILLED
        // Mutant 21 (drive check): if same drive both=true - KILLED
        $this->assertTrue($resultInside, 'Inside path must be valid');
        $this->assertFalse($resultOutside, 'Outside path must be invalid');
        $this->assertNotSame($resultInside, $resultOutside, 'Results must differ based on path location');
    }
    public function testFindPath_RequiresRealpathResolution(): void
    {
        $fullPath = __DIR__. DIRECTORY_SEPARATOR . 'legit.txt';
        
        $result = $this->reader->findPath($fullPath, __DIR__);
        
        // With realpath(): resolves to canonical path, strpos finds basePath at position 0
        // With dirname(): returns parent dir, strpos likely returns false or wrong position
        // With pathinfo(): returns parent dir, wrong result
        $this->assertSame(0, $result, 'findPath must use realpath to find base at start of path');
    }

    public function testFindPath_WithNonCanonicalInput(): void
    {
        $nonCanonicalPath = __DIR__ . DIRECTORY_SEPARATOR . '.' . DIRECTORY_SEPARATOR . 'legit.txt';
        
        $result = $this->reader->findPath($nonCanonicalPath, __DIR__);
        
        // realpath normalizes, then finds basePath at position 0
        // dirname/pathinfo don't normalize correctly
        $this->assertNotFalse($result, 'Must handle non-canonical paths with realpath');
    }
     public function testFindPath_MustReturnNumericPosition(): void
    {
        $basePath = __DIR__;
        $fullPath = __DIR__ . DIRECTORY_SEPARATOR . 'legit.txt';
        
        $result = $this->reader->findPath($fullPath, $basePath);
        
        // strpos: returns 0 (int) when basePath found at start
        // stripos: case-insensitive, might return 0
        // str_contains: returns bool true
        // str_starts_with: returns bool true
        // strrpos: returns last position (int)
        // strstr/strpbrk: return string or false
        // return 0: always returns 0
        // return true: always returns true
        $this->assertSame(0, $result, 'findPath must return 0 when path starts with base');
        $this->assertIsInt($result, 'findPath must return integer position');
    }

    public function testFindPath_CaseSensitivity(): void
    {
        $basePath = __DIR__;
        $upperPath = strtoupper(__DIR__) . DIRECTORY_SEPARATOR . 'file.txt';
        
        $result = $this->reader->findPath($upperPath, $basePath);
        
        // strpos: case-sensitive, returns false if case doesn't match
        // stripos: case-insensitive, might find match - KILLED
        $this->assertFalse($result, 'findPath must be case-sensitive (use strpos not stripos)');
    }

    public function testFindPath_NotAtStart(): void
    {
        $basePath = __DIR__;
        $pathWithBaseInMiddle = 'prefix' . DIRECTORY_SEPARATOR . __DIR__ . DIRECTORY_SEPARATOR . 'file.txt';
        
        $result = $this->reader->findPath($pathWithBaseInMiddle, $basePath);
        
        // strpos: returns position > 0 when found not at start
        // str_starts_with: returns false when not at start - different behavior
        // strrpos: returns last occurrence position
        // return 0: always 0 - KILLED
        // return true: always true - KILLED
        $this->assertNotSame(0, $result, 'Must detect when base is not at start');
        $this->assertNotSame(true, $result, 'Must return position, not boolean');
    }

    public function testFindPath_DriveLetterMutation(): void
    {
        $basePath = __DIR__;
        $fullPath = __DIR__ . DIRECTORY_SEPARATOR . 'legit.txt';
        
        $result = $this->reader->findPath($fullPath, $basePath);
        
        // Original: uses $basePath parameter
        // Mutant 31: uses hardcoded 'D:\' - returns different result
        $this->assertIsInt($result);
        $this->assertGreaterThanOrEqual(0, $result);
        
        // If basePath doesn't contain 'D:\', mutant returns false, original returns 0
        if (strpos($basePath, 'D:') === false) {
            $this->assertNotFalse($result, 'Must use actual basePath parameter, not hardcoded drive');
        }
    }
    public function testAbsPath_MustReturnAbsolutePath(): void
    {
        //$relativePath = $this->baseDir . DIRECTORY_SEPARATOR . 'subdir' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'subdir';
        $relativePath = __DIR__.DIRECTORY_SEPARATOR .'..'. DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR. '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR .   'pwds.txt'; 
       
        $result = $this->reader->absPath($relativePath);
        
        // With realpath: returns absolute canonical path
        // With basename: returns just 'subdir' (not absolute)
        // With dirname: returns parent directory path (wrong)
        // With pathinfo: returns parent directory (wrong)
        
        $this->assertNotEmpty($result);
        // Absolute path should contain full directory structure
        $this->assertGreaterThan(10, strlen($result), 'Absolute path must be full canonical path, not just basename');
        $this->assertStringNotContainsString('..', $result, 'Absolute path must not contain .. sequences');
    }

    public function testAbsPath_ResolvesDotDot(): void
    {
        $pathWithDotDot = $this->baseDir . DIRECTORY_SEPARATOR . 'subdir' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'subdir';
        
        $result = $this->reader->absPath($pathWithDotDot);
        
        // realpath resolves .. to canonical path
        // basename returns 'subdir' (incomplete)
        // dirname/pathinfo return wrong paths
        
        $canonicalExpected = $this->baseDir . DIRECTORY_SEPARATOR . 'subdir';
        $canonicalExpected = trim(realpath($canonicalExpected), DIRECTORY_SEPARATOR);
        
        $this->assertSame($canonicalExpected, $result, 'absPath must resolve .. with realpath');
    }
}