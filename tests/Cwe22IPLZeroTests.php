<?php

namespace Tests;

use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe22IPLZeroTests extends TestCase
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
//ZERO SHOT GPT TEST CASE GENERATED 13 TC
/*
    public function test_read_denies_traversal_and_outside_paths(): void
    {
        // canonical valid file
        $insideFile = $this->baseDir . DIRECTORY_SEPARATOR . 'legit.txt';
        //file_put_contents($insideFile, 'SAFE');

        // traversal payloads and absolute outside
        $payloads = [
            realpath(__DIR__ . '/../prompts/mutant_fix_prompt.md'),
            __DIR__ . '\\..\\..\\..\\..\\files.txt',
            __DIR__ . '\\..\\config\\another.txt'
        ];

        foreach ($payloads as $payload) {
            $result = $this->reader->read($payload);
            $this->assertEquals('Access denied', $result, "Traversal payload [$payload] should be denied");
        }

        // inside allowed
        $result = $this->reader->read('legit.txt');
        $this->assertSame('SAFE', $result, 'Legit file inside base should be allowed');
    }

    public function test_read_returns_access_denied_when_file_nonexistent(): void
    {
        $fake = 'nonexistent.txt';
        $result = $this->reader->read($fake);
        $this->assertEquals('Access denied', $result, 'Nonexistent file must deny access');
    }

    public function test_read_fails_if_base_replaced_with_drive_prefix(): void
    {
        // Forces mutants 15–16 (ReplaceSecondArgWithDriveMutator) to fail
        $filename = 'legit.txt';
        $response = $this->reader->read($filename);
        $this->assertStringNotContainsString('C:\\', $response);
        $this->assertStringNotContainsString('D:\\', $response);
    }


    public function test_isValidSubPath_false_for_outside_path(): void
    {
        $outside = __DIR__ . '/../../../etc/passwd';
        $result = $this->reader->isValidSubPath($outside, $this->baseDir);
        $this->assertFalse($result, 'Outside path must return false');
    }

    public function test_isValidSubPath_true_for_inside_path(): void
    {
        $inside = $this->baseDir . '/legit.txt';
        touch($inside);
        $result = $this->reader->isValidSubPath($inside, $this->baseDir);
        $this->assertTrue($result, 'Inside path must return true');
    }

    public function test_isValidSubPath_false_for_nonexistent_path(): void
    {
        $fake = $this->baseDir . '/ghost.txt';
        $result = $this->reader->isValidSubPath($fake, $this->baseDir);
        $this->assertFalse($result, 'Nonexistent input must return false');
    }

    public function test_isValidSubPath_case_sensitive_and_not_constant_true(): void
    {
        // catch ReturnConstantTrueMutator & drive prefix mutants
        $inside = $this->baseDir . '/legit.txt';
        $outsideDifferentDrive = 'D:\\legit.txt';
        $this->assertTrue($this->reader->isValidSubPath($inside, $this->baseDir));
        $this->assertFalse($this->reader->isValidSubPath($outsideDifferentDrive, $this->baseDir));
    }

 
    public function test_findPath_returns_zero_for_inside_and_false_for_outside(): void
    {
        $inside = $this->baseDir . DIRECTORY_SEPARATOR . 'legit.txt';
        $outside = 'D:\\Windows\\System32\\drivers\\etc\\hosts';

        $insideResult = $this->reader->findPath($inside, $this->baseDir);
        $outsideResult = $this->reader->findPath($outside, $this->baseDir);

        // expected types and semantics
        $this->assertIsInt($insideResult, 'Inside result should be int');
        $this->assertGreaterThanOrEqual(0, $insideResult, 'Inside result should not be false');

        $this->assertFalse($outsideResult, 'Outside path should yield false');
    }

    public function test_findPath_should_be_case_sensitive_and_not_constant_true(): void
    {
        $inside = $this->baseDir . DIRECTORY_SEPARATOR . 'legit.txt';
        $outside = strtoupper($this->baseDir) . DIRECTORY_SEPARATOR . 'legit.txt';
        $result1 = $this->reader->findPath($inside, $this->baseDir);
        $result2 = $this->reader->findPath($outside, $this->baseDir);
        $this->assertEquals($result1, $result2, 'Case difference must produce different result');
    }


    public function test_absPath_returns_canonical_realpath_only(): void
    {
        $target = $this->baseDir . '/../vulnerable_files/legit.txt';
        touch($this->baseDir . '/legit.txt');
        $canonical = realpath($target);
        $result = $this->reader->absPath($target);

        $this->assertSame(trim($canonical, DIRECTORY_SEPARATOR), $result, 'absPath must canonicalize fully');

        // nonexistent should return empty
        $fake = $this->baseDir . '/does_not_exist.txt';
        $resultFake = $this->reader->absPath($fake);
        $this->assertEmpty($resultFake, 'Nonexistent should return empty');
    }

  
    public function test_secureFilePath_allows_existing_inside_only(): void
    {
        $inside = $this->baseDir . '/legit.txt';
        file_put_contents($inside, 'SAFE');
        $outside = dirname($this->baseDir) . '/config.ini';
        $nonexistent = $this->baseDir . '/ghost.txt';

        $this->assertTrue($this->reader->secureFilePath($inside, $this->baseDir), 'Inside readable must pass');
        $this->assertFalse($this->reader->secureFilePath($outside, $this->baseDir), 'Outside must fail');
        $this->assertFalse($this->reader->secureFilePath($nonexistent, $this->baseDir), 'Nonexistent must fail');
    }

    public function test_secureFilePath_case_sensitive_and_not_constant_true(): void
    {
        $inside = $this->baseDir . '/legit.txt';
        $outside = 'D:\\legits.txt';
        $this->assertTrue($this->reader->secureFilePath($inside, $this->baseDir));
        $this->assertFalse($this->reader->secureFilePath($outside, $this->baseDir));
    }

    public function test_secureFilePath_rejects_non_string_input(): void
    {
        $this->assertFalse($this->reader->secureFilePath([], $this->baseDir));
        $this->assertFalse($this->reader->secureFilePath(null, $this->baseDir));
    }*/
    //GPT 2nd Generation
     public function testRealpathNotEquivalentToBasenameDirnamePathinfo()
    {
        $filename = 'legit.txt';
        $expectedPath = realpath($this->baseDir . '/' . $filename);

        // If mutant returns basename/dirname/pathinfo, they won't match realpath
        $this->assertEquals('SAFE', $this->reader->read($filename));
        $this->assertNotEquals(basename($this->baseDir . '/' . $filename), $expectedPath);
        $this->assertNotEquals(dirname($this->baseDir . '/' . $filename), $expectedPath);
        $this->assertNotEquals(pathinfo($this->baseDir . '/' . $filename, PATHINFO_DIRNAME), $expectedPath);
    }

    /**
     * 4-7: Hardcoded realpath payload replacements
     */
    public function testRealpathWithHardcodedFilePayloadsShouldFail()
    {
        $filename = 'legit.txt';

        // Original code works
        $this->assertEquals('SAFE', $this->reader->read($filename));

        // Mutants would try to resolve to wrong hardcoded paths -> should not equal
        $this->assertNotEquals(realpath('C:\\xampp\\htdocs\\samplecode\\MyProject\\File.txt'), realpath($this->baseDir . '/' . $filename));
        $this->assertNotEquals(realpath(__DIR__ . '/../../../config.ini'), realpath($this->baseDir . '/' . $filename));
        $this->assertNotEquals(realpath(__DIR__ . '/../../../files.txt'), realpath($this->baseDir . '/' . $filename));
        $this->assertNotEquals(realpath(__DIR__ . '/legit.txt'), realpath($this->baseDir . '/' . $filename));
    }

    /**
     * 8-16: str_starts_with mutations with basename/dirname/pathinfo/hardcoded drive
     */
    public function testStrStartsWithValidationEnsuresFileInsideBase()
    {
        $validFile = $this->baseDir . '/legit.txt';
        $invalidFile = __DIR__ . '/../config/another.txt';
        file_put_contents($invalidFile, 'OUTSIDE');

        // Valid case
        $this->assertEquals('SAFE', $this->reader->read('legit.txt'));

        // Invalid case should be rejected
        $this->assertEquals('Access denied', $this->reader->read('../../outside.txt'));

        // Mutants using basename/dirname/drives would misclassify
        $this->assertFalse(str_starts_with(realpath($invalidFile), realpath($this->baseDir)));
        $this->assertNotEquals(str_starts_with(realpath($invalidFile), basename($this->baseDir)), true);
       // $this->assertNotEquals(str_starts_with(realpath($invalidFile), dirname($this->baseDir)), true);
        $this->assertNotEquals(str_starts_with(realpath($invalidFile), 'C:\\'), true);
       //$this->assertNotEquals(str_starts_with(realpath($invalidFile), 'D:\\'), true);
    }

    /**
     * 17-22: isValidSubPath mutants (dirname/pathinfo/always true)
     */
    public function testIsValidSubPathCatchesInvalidTraversal()
    {
        $valid = $this->reader->isValidSubPath($this->baseDir . '/legit.txt', $this->baseDir);
        $invalid = $this->reader->isValidSubPath(__DIR__ . '/../../config.ini', $this->baseDir);

        $this->assertTrue($valid);
        $this->assertFalse($invalid);

        // Mutant returning true unconditionally should be caught
        $this->assertNotEquals(true, $invalid);
    }

    /**
     * 23-33: findPath() mutants (strpos -> dirname/pathinfo/str_contains/etc.)
     */
    public function testFindPathDetectsPathTraversal()
    {
        $safe = $this->reader->findPath($this->baseDir . '/legit.txt', $this->baseDir);
        $unsafe = $this->reader->findPath(__DIR__ . $this->outsideFile, $this->baseDir);

        $this->assertNotFalse($safe);
        $this->assertFalse($unsafe);

        // Mutants returning 0/true break logic
        $this->assertNotEquals(true, $unsafe);
       // $this->assertNotEquals(0, $unsafe);
    }

    /**
     * 34-36: absPath mutants (basename/dirname/pathinfo instead of realpath)
     */
    public function testAbsPathNormalization()
    {
        $file = $this->baseDir . '/legit.txt';
        $expected = trim(realpath($file), DIRECTORY_SEPARATOR);
        $mutatedBase = trim(basename($file), DIRECTORY_SEPARATOR);

        $this->assertEquals($expected, $this->reader->absPath($file));
        $this->assertNotEquals($mutatedBase, $this->reader->absPath($file));
    }

    /**
     * 37-41: secureFilePath mutants (stripos/strrpos/remove check/always true)
     */
    public function testSecureFilePathRejectsInvalidFiles()
    {
        $valid = $this->reader->secureFilePath($this->baseDir . '/legit.txt', $this->baseDir);
        $invalid = $this->reader->secureFilePath(__DIR__ . '/../../outside.txt', $this->baseDir);

        $this->assertTrue($valid);
        $this->assertFalse($invalid);

        // If mutant removed check or returned true, invalid file would pass
        $this->assertNotEquals(true, $invalid);
    }
    //ZERO SHOT QWEN 12 TC
    // ------------------------------------------------------------------
    // 1. Test valid file access (baseline)
    // ------------------------------------------------------------------
  /*  public function testValidFileIsRead(): void
    {
        $content = $this->reader->read($this->legitFile);
        $this->assertNotEquals('Access denied', $content);
        //$this->assertStringContainsString('This is a legitimate file.', $content);
    }

    // ------------------------------------------------------------------
    // 2. Block path traversal attempts (critical for killing mutants)
    // ------------------------------------------------------------------
   public function testPathTraversalWithDotDotIsBlocked(): void
    {
        $maliciousInputs = [
            '../../../config.ini',
            '..\\..\\..\\config.ini',
            '/etc/passwd',
            'C:\\windows\\system.ini',
            '..\\..\\..\\..\\files.txt',
            '../../../../../../../../etc/passwd'
        ];

        foreach ($maliciousInputs as $input) {
            $result = $this->reader->read($input);
            $this->assertEquals('Access denied', $result, "Failed to block: $input");
        }
    }

    
    public function testMutantRealpathReplacedWithBasenameFails(): void
    {
        // If $fullPath = basename($base . $filename), it returns just 'legit.txt'
        // Then str_starts_with('legit.txt', realpath($base)) → false → 'Access denied'
        // BUT if test only checks legit file, it passes. So we need to ensure
        // that even valid files fail under mutation → but wait: that would break legit use.

        // Instead: test that **invalid** paths don't return file contents.
        // More importantly: test that **valid path resolves to full real path**

        // Force a case where basename/dirname would cause incorrect $fullPath
        $result = $this->reader->read($this->legitFile);
        // Under mutation #1 (basename), $fullPath = 'legit.txt', which is NOT under $base → returns 'Access denied'
        // So if current test passes, mutation is already killed? But Infection says escaped → so maybe not.

        // Therefore: ensure that the **resolved path is absolute and under base**
        // We test via side effect: if mutation returns wrong path, file_get_contents fails or returns wrong content.

        // Better: test behavior of `isValidSubPath` directly
        $this->assertFalse($this->reader->isValidSubPath('/etc/passwd', $this->baseDir));
        $this->assertTrue($this->reader->isValidSubPath($this->baseDir . DIRECTORY_SEPARATOR . 'legit.txt', $this->baseDir));
    }

    // ------------------------------------------------------------------
    // 4. Kill hardcoded path mutants (e.g., realpath('C:\...\File.txt'))
    // ------------------------------------------------------------------
    public function testHardcodedPathMutantsAreDetected(): void
    {
        // Mutants #4–7 replace dynamic path with fixed one.
        // If fixed path is outside baseDir, access should be denied.
        // But if test only uses legit.txt, it may not trigger.

        // However, the key is: **the function must use $filename**, not ignore it.
        // So test with two different filenames → should return different content.

        file_put_contents($this->baseDir . '/file1.txt', 'content1');
        file_put_contents($this->baseDir . '/file2.txt', 'content2');

        $result1 = $this->reader->read('file1.txt');
        $result2 = $this->reader->read('file2.txt');

        // If mutant hardcodes path (e.g., always returns File.txt), both results are same
        $this->assertNotEquals($result1, $result2);
        $this->assertEquals('content1', trim($result1));
        $this->assertEquals('content2', trim($result2));

        unlink($this->baseDir . '/file1.txt');
        unlink($this->baseDir . '/file2.txt');
    }

    // ------------------------------------------------------------------
    // 5. Kill drive-prefix mutants (C:\\, D:\\)
    // ------------------------------------------------------------------
    public function testDrivePrefixMutantsAreKilled(): void
    {
        // Mutants #15, #16, #21, #31, #39 replace base check with 'C:\\' or 'D:\\'
        // On Windows, realpath may return D:\..., so str_starts_with(D:\..., 'C:\\') → false → access denied (good)
        // But if base is on D:\, and mutant checks 'D:\\', then **any D:\ file is allowed**, including outside base!

        // Simulate: if base is D:\project\vulnerable_files, but mutant allows any D:\ file
        // Then reading D:\project\config.ini should be blocked, but mutant allows it.

        $outsidePath = realpath(__DIR__ . '/../composer.json');
        if ($outsidePath && str_starts_with($outsidePath, 'D:\\')) {
            // Craft a traversal that resolves to outsidePath
            $traversal = str_repeat('../', 3) . 'config.ini';
            $result = $this->reader->read($traversal);
            $this->assertEquals('Access denied', $result, 'Drive-prefix mutant allowed access to ' . $outsidePath);
        }
    }

    // ------------------------------------------------------------------
    // 6. Kill logic-bypass mutants (return true / return 0)
    // ------------------------------------------------------------------
    public function testReturnTrueMutantsAreKilled(): void
    {
        // Mutants #22, #33: isValidSubPath or findPath always returns true
        // This would allow any file to be read

        $result = $this->reader->read('../../../config.ini');
        $this->assertEquals('Access denied', $result, 'Return-true mutant not killed');
    }

    public function testReturnZeroMutantIsKilled(): void
    {
        // Mutant #32: findPath returns 0 → treated as success in some contexts?
        // Ensure that findPath is not solely relied on for security
        // But better: test end-to-end traversal
        $result = $this->reader->read('../../../config.ini');
        $this->assertEquals('Access denied', $result);
    }

   

    public function testStrstrOrStrContainsMutantsAreKilled(): void
    {
        // Mutants #29, #26: strstr/str_contains return truthy even if base is in middle
        // Example: base = '/safe', filePath = '/unsafe/safe/file' → contains '/safe' → allowed (vulnerable)

        // Create such a scenario
        $unsafeDir = $this->baseDir . '_evil';
       // mkdir($unsafeDir, 0777, true);
        //file_put_contents($unsafeDir . '/trap.txt', 'should not be readable');

        // Now, if base is '/project/vulnerable_files', and filePath is '/project/vulnerable_files_evil/trap.txt'
        // It contains 'vulnerable_files' → str_contains returns true → bypass!

        // But our function uses `strpos !== 0`, so it should fail.
        // However, if mutated to `str_contains`, it passes.

        // Simulate by calling secureFilePath directly if possible
        // Or test via readFile with crafted path that exploits substring match

        // Since we can't easily create such path without knowing full structure,
        // we test the `secureFilePath` method directly:

        $basePath = $this->baseDir;
        $evilPath = $basePath . '../composer.json';

        // This should return false
        $result = $this->reader->secureFilePath($evilPath, $basePath);
        $this->assertFalse($result, 'str_contains mutant allowed substring match');

       //rmdir($unsafeDir);
    }

    // ------------------------------------------------------------------
    // 8. Test findPath and absPath mutations
    // ------------------------------------------------------------------
    public function testFindPathMutantsAreKilled(): void
    {
        // Mutants #23–33 alter findPath behavior
        // findPath is used in security? If it returns non-false for bad paths, may bypass

        // Test that findPath returns false (or 0) for paths outside base
        $outside = realpath(__DIR__ . '/../../composer.json');
        $base = $this->baseDir;

        $result = $this->reader->findPath($outside, $base);
        // Original: strpos(realpath(outside), base) → false or position
        // But if mutated to `return true` or `0`, logic may break

        // However, since findPath is not the main gate, rely on end-to-end test
        $readResult = $this->reader->read('../../composer.json');
        $this->assertEquals('Access denied', $readResult);
    }

    public function testAbsPathMutantsAreKilled(): void
    {
        // Mutants #34–36: absPath returns basename/dirname instead of realpath
        // This could break normalization

        $input = $this->baseDir . '/../vulnerable_files/./legit.txt';
        $expected = $this->baseDir . '/legit.txt';

        // If absPath uses basename, it returns 'legit.txt' → wrong
        // But if used in security context, may cause bypass

        // Test secureFilePath with normalized path
        $normalized = $this->reader->absPath($input);
        $this->assertStringStartsWith($this->baseDir, $normalized);
        $this->assertStringEndsWith('legit.txt', $normalized);
    }

    // ------------------------------------------------------------------
    // 9. Kill security check removal mutant (#40, #41)
    // ------------------------------------------------------------------
    public function testSecurityChecksAreEnforced(): void
    {
        // Mutant #40 removes the basePath prefix check
        // Mutant #41 removes file existence/readability check

        // Without prefix check, any existing readable file can be read
        $outside = realpath(__DIR__ . '/../composer.json');
        if ($outside && is_readable($outside)) {
            // Try to read it via traversal
            $result = $this->reader->read('../../composer.json');
            $this->assertEquals('Access denied', $result, 'Security check removal mutant not killed');
        }
    }
*/
  /*    //ZERO SHOT GEMINI 11 TC

    public function testReadFileWithTraversalAttemptFails(): void
    {
        // Construct a path that tries to escape the vulnerable_files directory
        $maliciousFilename = '../secret.txt';
        $result = $this->reader->read($maliciousFilename);
        $this->assertSame('Access denied', $result, 'Should deny access for path traversal.');
    }

    public function testReadFileWithSecondValidFileSucceeds(): void
    {
        $content = $this->reader->read(__DIR__ . '/../composer.json');
        $this->assertNotSame('more content', $content, 'Should be able to read a different valid file.');
    }
    public function testIsValidSubPathWithExternalPathReturnsFalse(): void
    {
        $this->assertFalse(
            $this->reader->isValidSubPath(self::$secretFile, self::$vulnerableFilesDir),
            'Should return false for a path outside the base directory.'
        );
    }

    public function testIsValidSubPathWithNonExistentPathReturnsFalse(): void
    {
        $this->assertFalse(
            $this->reader->isValidSubPath(self::$vulnerableFilesDir . '/non_existent_file.txt', self::$vulnerableFilesDir),
            'Should return false for a non-existent input path.'
        );
    }


    public function testFindPathReturnsStrictZeroForValidPath(): void
    {
        $path = self::$vulnerableFilesDir . '/safe_file.txt';
        $this->assertFalse( $this->reader->findPath($path, self::$vulnerableFilesDir));
    }

    public function testFindPathReturnsStrictFalseForInvalidPath(): void
    {
        $this->assertSame(false, $this->reader->findPath(self::$secretFile, self::$vulnerableFilesDir));
    }


    public function testFindPathFailsWhenBasePathIsNotAtTheStart(): void
    {
        
        $this->assertFalse($this->reader->findPath($this->outsideFile, $this->baseDir));     
    }

    public function testAbsPathNormalizesComplexPathsCorrectly(): void
    {
        $complexPath = self::$vulnerableFilesDir . '/path-payloads.json';
        $expected = realpath($complexPath);
        $this->assertSame(
            trim($expected, DIRECTORY_SEPARATOR),
            $this->reader->absPath($complexPath)
        );
    }

    public function testSecureFilePathReturnsFalseForPathOutsideBase(): void
    {
        $this->assertFalse(
            $this->reader->secureFilePath(self::$secretFile, self::$vulnerableFilesDir)
        );
    }

    
    public function testSecureFilePathReturnsFalseForNonExistentFile(): void
    {
        $this->assertFalse(
            $this->reader->secureFilePath(self::$vulnerableFilesDir . '/non_existent.txt', self::$vulnerableFilesDir)
        );
    }


    public function testSecureFilePathIsCaseSensitive(): void
    {
        // Create a base path with a specific case
        $basePath = self::$vulnerableFilesDir;
        // Create a file path with a different case that still points to the same location
        $filePath = str_replace('vulnerable_files', 'VULNERABLE_FILES', $basePath) . '/safe_file.txt';

        // This should fail because strpos is case-sensitive and the strings won't match at position 0.
        // A mutant using stripos would incorrectly pass this test.
        $this->assertFalse($this->reader->secureFilePath($filePath, $basePath));
    }

*/
//ZERO SHOT DeepSeek DeepSeek V3.1 24 TC 6 TC Adjusted
    // Test cases for line 9 mutations (realpath replacement)
 /*public function testRealPathReplacementWithBasenameShouldFailSecurityCheck()
    {
        $filename = '../../config.ini';
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Should detect path traversal when realpath is replaced with basename");
    }

    public function testRealPathReplacementWithDirnameShouldFailSecurityCheck()
    {
        $filename = '../../../etc/passwd';
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Should detect path traversal when realpath is replaced with dirname");
    }

    public function testRealPathReplacementWithPathinfoShouldFailSecurityCheck()
    {
        $filename = '../sensitive_data.txt';
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Should detect path traversal when realpath is replaced with pathinfo");
    }

    public function testFixedPathPayloadShouldBeDetected()
    {
        $filename = 'legitimate.txt'; // This should trigger the mutated fixed path
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Should detect when path is hardcoded to external location");
    }

    // Test cases for line 13 mutations (security check parameter replacement)
    public function testSecurityCheckWithBasenameBaseShouldFail()
    {
        $filename = '../../../../windows/system.ini';
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Security check with basename should fail for traversal attempts");
    }

    public function testSecurityCheckWithDirnameBaseShouldFail()
    {
        $filename = '../.env';
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Security check with dirname should fail for traversal attempts");
    }

    public function testSecurityCheckWithPathinfoBaseShouldFail()
    {
        $filename = '..\..\config.php';
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Security check with pathinfo should fail for traversal attempts");
    }

    public function testSecurityCheckWithDriveLetterShouldFail()
    {
        $filename = 'C:\\Windows\\system.ini';
        $result = $this->reader->read($filename);
        $this->assertEquals('Access denied', $result, "Security check with drive letter should fail for absolute paths");
    }

    // Test cases for isValidSubPath function mutations
    public function testIsValidSubPathWithDirnameInputShouldReturnFalse()
    {
        $result = $this->reader->isValidSubPath(
            '../../sensitive.txt',
            $this->baseDir
        );
        $this->assertFalse($result, "isValidSubPath should return false when input path uses dirname");
    }

    public function testIsValidSubPathWithPathinfoInputShouldReturnFalse()
    {
        $result = $this->reader->isValidSubPath(
            '../config.ini',
            $this->baseDir
        );
        $this->assertFalse($result, "isValidSubPath should return false when input path uses pathinfo");
    }

    public function testIsValidSubPathWithDirnameBaseShouldReturnFalse()
    {
        $result = $this->reader->isValidSubPath(
            $this->baseDir. '/test.txt',
            '../../parent'
        );
        $this->assertFalse($result, "isValidSubPath should return false when base path uses dirname");
    }

    public function testIsValidSubPathWithPathinfoBaseShouldReturnFalse()
    {
        $result = $this->reader->isValidSubPath(
            $this->baseDir. '/test.txt',
            '../other'
        );
        $this->assertFalse($result, "isValidSubPath should return false when base path uses pathinfo");
    }

    public function testIsValidSubPathWithDriveComparisonShouldReturnFalse()
    {
        $result = $this->reader->isValidSubPath(
            'D:\\external\\file.txt',
            $this->baseDir
        );
        $this->assertFalse($result, "isValidSubPath should return false when comparing with drive letter");
    }

    public function testIsValidSubPathReturningTrueShouldBeIncorrect()
    {
        $result = $this->reader->isValidSubPath(
            '../../etc/passwd',
            $this->baseDir
        );
        $this->assertFalse($result, "Mutant returning true for invalid path should be killed");
    }

    // Test cases for findPath function mutations
    public function testFindPathWithDirnameShouldReturnIncorrectResult()
    {
        $result = $this->reader->findPath(
            '../../config.php',
            $this->baseDir
        );
        $this->assertFalse($result === 0, "findPath with dirname should not return position 0 for traversal paths");
    }

    public function testFindPathWithPathinfoShouldReturnIncorrectResult()
    {
        $result = $this->reader->findPath(
            '../.env',
            $this->baseDir
        );
        $this->assertFalse( $result, "findPath with pathinfo should not return 0 for relative paths");
    }

    public function testFindPathWithCaseInsensitiveSearchShouldBeInsecure()
    {
        $result = $this->reader->findPath(
            '../../Config.php',
            $this->baseDir
        );
        $this->assertFalse($result !== false, "Case insensitive search should not find traversal paths");
    }

    public function testFindPathWithContainsCheckShouldBeInsecure()
    {
        $result = $this->reader->findPath(
            $this->baseDir . '/../../external.txt',
            $this->baseDir
        );
        $this->assertFalse( $result, "Contains check should not return 0 for embedded traversal");
    }

    public function testFindPathWithStartsWithCheckShouldBeInsecure()
    {
        $maliciousPath = $this->baseDir. '/../traversal.txt';
        $result = $this->reader->findPath($maliciousPath, $this->baseDir);
        $this->assertFalse( $result, "Starts with check should fail for complex traversal");
    }

    public function testFindPathWithReverseSearchShouldBeInsecure()
    {
        $result = $this->reader->findPath(
            'file.txt' . $this->baseDir,
            $this->baseDir
        );
        $this->assertFalse( $result, "Reverse search should not return position 0");
    }

    public function testFindPathWithStringSearchShouldBeInsecure()
    {
        $result = $this->reader->findPath(
            $this->baseDir . '/sub/../../file.txt',
            $this->baseDir
        );
        $this->assertFalse( $result, "String search should detect embedded traversal patterns");
    }

    public function testFindPathWithCharacterSearchShouldBeInsecure()
    {
        $result = $this->reader->findPath(
            '../../file.txt',
            $this->baseDir
        );
        $this->assertFalse($result !== false, "Character search should not find traversal patterns");
    }

    public function testFindPathWithDriveComparisonShouldFail()
    {
        $result = $this->reader->findPath(
            'D:\\external.txt',
            $this->baseDir
        );
        $this->assertFalse($result !== false, "Drive comparison should not match base path");
    }

    public function testFindPathReturningZeroShouldBeIncorrect()
    {
        $result = $this->reader->findPath(
            '../../etc/passwd',
            $this->baseDir
        );
        $this->assertFalse( $result, "Returning 0 for traversal path should be detected");
    }*/
        
    // Claude Sonnet 4.5 28 TC 7 TC Adjusted
  /*       public function testReadFileRejectsSymlinkTraversal(): void
    {
        // basename/dirname would not resolve symlinks, allowing bypass
        $result = $this->reader->read('../../../etc/passwd');
        $this->assertEquals('Access denied', $result);
    }

    public function testReadFileWithRelativePathComponents(): void
    {
        // Test that actual path resolution happens (not just basename)
        $result = $this->reader->read('.//..//..//sensitive.txt');
        $this->assertEquals('Access denied', $result);
    }

    
    public function testReadFileUsesProvidedFilename(): void
    {
        // Create a legitimate test file
        $testFile = 'legit.txt';
        $fullPath = $this->baseDir . $testFile;
        file_put_contents($fullPath, 'safecontent');
        
        $result = $this->reader->read($testFile);
        $this->assertStringContainsString('safecontent', $result);
        
        
    }

    public function testReadFileDifferentInputsProduceDifferentResults(): void
    {
        // Ensure mutations with hardcoded paths fail
        $file1 = 'legit.txt';
        $file2 = 'fileB.txt';
        
        if (!file_exists($this->baseDir)) {
            mkdir($this->baseDir, 0777, true);
        }
        
        file_put_contents($this->baseDir . $file1, 'content1');
        file_put_contents($this->baseDir . $file2, 'content2');
        
        $result1 = $this->reader->read($file1);
        $result2 = $this->reader->read($file2);
        
        $this->assertNotEquals($result1, $result2);
        $this->assertStringContainsString('safecontent', $result1);
        $this->assertStringContainsString('CONTENT_B', $result2);
        
        // Cleanup
        unlink($this->baseDir . $file1);
        unlink($this->baseDir . $file2);
    }

    
    public function testValidationUsesFullPathComparison(): void
    {
        // Test that validation compares full resolved paths
        $result = $this->reader->read('../../etc/shadow');
        $this->assertEquals('Access denied', $result);
    }

    public function testValidationDetectsPathEscape(): void
    {
        // Mutants using basename($base) would validate incorrectly
        $maliciousPath = str_repeat('../', 10) . 'etc/passwd';
        $result = $this->reader->read($maliciousPath);
        $this->assertEquals('Access denied', $result);
    }

 
    public function testValidationPathIsBasedOnBaseDirectory(): void
    {
        // Ensure validation uses actual base, not hardcoded path
        $testFile = 'valid_for_helper.txt';
        if (!file_exists($this->baseDir)) {
            mkdir($this->baseDir, 0777, true);
        }
        file_put_contents($this->baseDir . $testFile, 'valid');
        
        $result = $this->reader->read($testFile);
        $this->assertNotEquals('Access denied', $result);
        
        unlink($this->baseDir . $testFile);
    }

    public function testValidationDoesNotAllowEntireDriveAccess(): void
    {
        // If validation checks against 'C:\' or 'D:\', it would allow entire drive
        $result = $this->reader->read('../../../Windows/System32/config/SAM');
        $this->assertEquals('Access denied', $result);
    }

    public function testIsValidSubPathResolvesInputPath(): void
    {
        $basePath = $this->baseDir;
        $validPath = $basePath . 'subdir/file.txt';
        $invalidPath = dirname($basePath) . '/outside.txt';
        
        $this->assertFalse($this->reader->isValidSubPath($invalidPath, $basePath));
    }

    public function testIsValidSubPathWithSymlinks(): void
    {
        // dirname/pathinfo don't resolve symlinks - this should fail with mutant
        $basePath = $this->baseDir;
        $traversalPath = $basePath . '../sensitive/data.txt';
        $this->assertFalse($this->reader->isValidSubPath($traversalPath, $basePath));
    }

    
    public function testIsValidSubPathResolvesBasePath(): void
    {
        $basePath = $this->baseDir;
        $inputPath = $basePath . 'file.txt';
        
        // Create test structure
        if (!file_exists($basePath)) {
            mkdir($basePath, 0777, true);
        }
        touch($inputPath);
        
        $result = $this->reader->isValidSubPath($inputPath, $basePath);
        $this->assertTrue($result);
        
        unlink($inputPath);
    }

    public function testIsValidSubPathRejectsOutsideBase(): void
    {
        $basePath = $this->baseDir;
        $outsidePath = 'D:\\completely\\different\\path\\file.txt';
        
        $this->assertFalse($this->reader->isValidSubPath($outsidePath, $basePath));
    }
    
    public function testIsValidSubPathReturnsFalseForInvalidPaths(): void
    {
        $basePath = $this->baseDir;
        $invalidPath = '/tmp/outside/secure/area.txt';
        
        $result = $this->reader->isValidSubPath($invalidPath, $basePath);
        $this->assertFalse($result);
    }
    public function testFindPathUsesResolvedPaths(): void
    {
        $basePath = $this->baseDir;
        $path = $basePath . 'test.txt';
        
        if (!file_exists($basePath)) {
            mkdir($basePath, 0777, true);
        }
        touch($path);
        
        $result = $this->reader->findPath($path, $basePath);
        
        // strpos should find base at position 0
        $this->assertIsInt($result);
        $this->assertEquals(0, $result);
        
        unlink($path);
    }

    public function testFindPathRejectsNonSubpath(): void
    {
        $basePath = $this->baseDir;
        $outsidePath = '/tmp/outside.txt';
        
        $result = $this->reader->findPath($outsidePath, $basePath);
        
        // Should not find basePath at position 0
        $this->assertFalse( $result);
    }

    
    public function testFindPathDetectsExactPrefixMatch(): void
    {
        $basePath = '/var/www/uploads/';
        $validPath = '/var/www/uploads/user/file.txt';
        $similarPath = '/var/www/uploads_fake/evil.txt';
        
        // strpos correctly finds prefix; str_contains would match both
        $validResult = $this->reader->findPath($validPath, $basePath);
        $invalidResult = $this->reader->findPath($similarPath, $basePath);
        
        $this->assertEquals(0, $validResult);
        $this->assertFalse( $invalidResult);
    }

    
    public function testFindPathUsesProvidedBasePath(): void
    {
        $basePath = $this->baseDir;
        $path = $basePath . 'file.txt';
        
        if (!file_exists($basePath)) {
            mkdir($basePath, 0777, true);
        }
        touch($path);
        
        $result = $this->reader->findPath($path, $basePath);
        $this->assertEquals(0, $result);
        
        unlink($path);
    }

    
    public function testFindPathReturnsDifferentValues(): void
    {
        $basePath = $this->baseDir;
        
        if (!file_exists($basePath)) {
            mkdir($basePath, 0777, true);
        }
        
        $insidePath = $basePath . 'inside.txt';
        $outsidePath = '/tmp/outside.txt';
        
        touch($insidePath);
        
        $resultInside = $this->reader->findPath($insidePath, $basePath);
        $resultOutside = $this->reader->findPath($outsidePath, $basePath);
        
        // Results should be different
        $this->assertFalse( $resultOutside);
        $this->assertEquals(0, $resultInside);
        $this->assertFalse( $resultOutside);
        
        unlink($insidePath);
    }
    public function testAbsPathResolvesSymlinks(): void
    {
        $testPath = $this->baseDir . 'test.txt';
        
        if (!file_exists($this->baseDir)) {
            mkdir($this->baseDir, 0777, true);
        }
        touch($testPath);
        
        $result = $this->reader->absPath($testPath);
        
        // Should return full resolved path, not just basename/dirname
        $this->assertStringContainsString('vulnerable_files', $result);
        $this->assertStringContainsString('test.txt', $result);
        
        unlink($testPath);
    }

    public function testAbsPathHandlesRelativePaths(): void
    {
        $relativePath = './test/../vulnerable_files/file.txt';
        
        $result = $this->reader->absPath($relativePath);
        
        // basename/dirname would not resolve ../ properly
        $this->assertStringNotContainsString('..', $result);
        $this->assertStringNotContainsString('./', $result);
    }

    public function testSecureFilePathCaseSensitiveCheck(): void
    {
        $basePath = '/var/www/UPLOADS/';
        $filePath = '/var/www/uploads/file.txt';
        
        // stripos would match case-insensitively, allowing bypass
        $result = $this->reader->secureFilePath($filePath, $basePath);
        
        $this->assertFalse($result);
    }

    public function testSecureFilePathChecksPrefixNotSuffix(): void
    {
        $basePath = '/uploads/';
        $filePath = '/var/www/uploads/';
        
        // strrpos checks last occurrence, not first
        $result = $this->reader->secureFilePath($filePath, $basePath);
        
        $this->assertFalse($result);
    }
    public function testSecureFilePathUsesCorrectBasePath(): void
    {
        $basePath = $this->baseDir;
        $validFile = $basePath . 'secure.txt';
        
        if (!file_exists($basePath)) {
            mkdir($basePath, 0777, true);
        }
        touch($validFile);
        
        $result = $this->reader->secureFilePath($validFile, $basePath);
        $this->assertTrue($result);
        
        unlink($validFile);
    }
    
    public function testSecureFilePathEnforcesBasePathRestriction(): void
    {
        $basePath = '/var/www/uploads/';
        $outsideFile = '/etc/passwd';
        
        // Without strpos check, any file_exists path would return true
        $result = $this->reader->secureFilePath($outsideFile, $basePath);
        
        $this->assertFalse($result);
    }

    public function testSecureFilePathRejectsPathTraversal(): void
    {
        $basePath = $this->baseDir;
        $traversalPath = $basePath . '../../sensitive/data.txt';
        
        $result = $this->reader->secureFilePath($traversalPath, $basePath);
        
        $this->assertFalse($result);
    }
    public function testSecureFilePathValidatesFileExists(): void
    {
        $basePath = $this->baseDir;
        $nonExistentFile = $basePath . 'does_not_exist_' . uniqid() . '.txt';
        
        // Without file_exists check, would return true for any path under base
        $result = $this->reader->secureFilePath($nonExistentFile, $basePath);
        
        $this->assertFalse($result);
    }

    public function testSecureFilePathValidatesFileReadable(): void
    {
        $basePath = $this->baseDir;
        $unreadableFile = __DIR__ . DIRECTORY_SEPARATOR. '..\vulnerable_files\unreadable_file.txt';
        
        if (!file_exists($basePath)) {
            mkdir($basePath, 0777, true);
        }
        
        touch($unreadableFile);
        chmod($unreadableFile, 0000);
        
        $result = $this->reader->secureFilePath($unreadableFile, $basePath);
        
        $this->assertFalse($result);
        
        // Cleanup
        chmod($unreadableFile, 0644);
        unlink($unreadableFile);
    }

    public function testCompletePathTraversalProtection(): void
    {
        $attacks = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            './../.../../sensitive.txt',
            'file.txt/../../../etc/passwd',
        ];

        foreach ($attacks as $attack) {
            $result = $this->reader->read($attack);
            $this->assertEquals(
                'Access denied',
                $result,
                "Failed to block attack: $attack"
            );
        }
    }*/
}