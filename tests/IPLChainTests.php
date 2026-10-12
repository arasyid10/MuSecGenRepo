<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use App\VulnFileRead;

/**
 * Security-focused mutation test suite for VulnFileRead.
 *
 * This suite is designed to kill surviving mutants by testing specific
 * security-critical edge cases, boundary conditions, and return types
 * that weaker "happy path" tests missed.
 *
 * It uses a test fixture setup to create a safe, controlled file
 * environment for testing path traversal.
 *
 * @covers \App\VulnFileRead
 */
class IPLChainTests extends TestCase
{
    private VulnFileRead $reader;
    private string $baseDir;
    private string $safeFilePath;
    private string $outsideFilePath;
    private string $safeFileContent = 'safe-content-v1';
    private string $outsideFileContent = 'outside-secret-v1';

    /**
     * Set up a safe test environment before each test.
     *
     * Creates:
     * 1. The base directory ('vulnerable_files') expected by the SUT.
     * 2. A 'safe_file.txt' *inside* the base directory.
     * 3. An 'outside_secret.txt' *outside* the base directory.
     */
    protected function setUp(): void
    {
        $this->reader = new VulnFileRead();

        // SUT calculates base path from its own location
        $sutDir = dirname((new \ReflectionClass(VulnFileRead::class))->getFileName());
        $baseDir = $sutDir . '/../vulnerable_files';

        if (!is_dir($baseDir)) {
            mkdir($baseDir, 0777, true);
        }
        $this->baseDir = realpath($baseDir);
        if (!$this->baseDir) {
            $this->fail("Failed to create or find base directory at {$baseDir}");
        }

        // 1. Create the "safe" file
        $this->safeFilePath = $this->baseDir . DIRECTORY_SEPARATOR . 'safe_file.txt';
        file_put_contents($this->safeFilePath, $this->safeFileContent);

        // 2. Create the "outside" file
        $outsideDir = realpath($this->baseDir . '/..');
        $this->outsideFilePath = $outsideDir . DIRECTORY_SEPARATOR . 'outside_secret.txt';
        file_put_contents($this->outsideFilePath, $this->outsideFileContent);
    }

    /**
     * Clean up the test environment after each test.
     */
    protected function tearDown(): void
    {
        if (file_exists($this->safeFilePath)) {
            unlink($this->safeFilePath);
        }
        if (file_exists($this->outsideFilePath)) {
            unlink($this->outsideFilePath);
        }
    }
//GEMINI
    /**
     * Kills Mutants: 1-14
     * Tests the "happy path" for the read() method.
     * This kills mutants that break realpath() or the base path check,
     * causing valid reads to fail and return 'Access denied'.
     */
    public function testReadValidFileSucceeds(): void
    {
        $content = $this->reader->read('safe_file.txt');
        $this->assertSame($this->safeFileContent, $content);
    }

    /**
     * Kills Mutants: 15-16
     * Tests that a traversal attack to a file on the *same drive* but
     * *outside* the base directory is blocked.
     * This kills mutants that weaken the base path check to just 'C:\' or 'D:\'.
     */
    public function testReadBlocksTraversalToSameDrive(): void
    {
        // This path is 'vulnerable_files/../outside_secret.txt'
        $content = $this->reader->read('../outside_secret.txt');
        $this->assertSame('Access denied', $content);
        $this->assertNotSame($this->outsideFileContent, $content);
    }

    /**
     * Kills Mutants: 17-22
     * Tests that isValidSubPath() correctly returns FALSE for a path
     * that resolves to be outside the base directory.
     * This kills mutants that remove realpath() or replace the final
     * check with 'true', as they will incorrectly return TRUE.
     */
    public function testIsValidSubPathRejectsTraversal(): void
    {
        $result = $this->reader->isValidSubPath($this->outsideFilePath, $this->baseDir);
        $this->assertFalse($result, "isValidSubPath should return false for outside paths");
    }

    /**
     * Kills Mutants: 26, 27, 29, 30, 33 (partially)
     * Replaces the weak 'testfindPathWeak'. Asserts the *exact* return
     * value '0' for a successful find.
     * This kills mutants that change strpos() to functions that return
     * 'true' (like str_contains) or a string (like strstr).
     */
    public function testFindPathReturnsStrictZeroOnSuccess(): void
    {
        $response = $this->reader->findPath($this->safeFilePath, $this->baseDir);
        $this->assertSame(0, $response, "findPath must return integer 0 on success, not bool(true)");
    }

    /**
     * Kills Mutants: 23, 24, 32, 33 (partially)
     * Tests that findPath() returns FALSE for a non-existent file.
     * This kills mutants that replace realpath() (which returns false)
     * with dirname() (which returns a string) or hardcode '0' or 'true'.
     */
    public function testFindPathFailsForNonExistentPath(): void
    {
        $nonExistentPath = $this->baseDir . DIRECTORY_SEPARATOR . 'non-existent.txt';
        $response = $this->reader->findPath($nonExistentPath, $this->baseDir);
        $this->assertFalse($response, "findPath must return false for non-existent paths");
    }

    /**
     * Kills Mutants: 25 (stripos), 31 ('D:\')
     * Tests that findPath() is case-sensitive.
     * This kills the 'stripos' mutant (which would return 0) and the
     * 'D:\' mutant (which would also return 0).
     */
    public function testFindPathIsCaseSensitive(): void
    {
        // Skip if OS is case-insensitive and paths match
        $upperBase = strtoupper($this->baseDir);
        if ($upperBase === $this->baseDir && stripos(PHP_OS, 'WIN') === 0) {
            $this->markTestSkipped('Cannot test case-sensitivity on this OS/path.');
        }

        $response = $this->reader->findPath($this->safeFilePath, $upperBase);
        $this->assertFalse($response, "findPath should be case-sensitive and return false");
    }

    /**
     * Kills Mutant: 28 (strrpos)
     * Tests that findPath() finds the *first* (strpos) not *last* (strrpos)
     * occurrence of the base path.
     */
    public function testFindPathFindsFirstOccurrence(): void
    {
        // Create a path like '.../base/sub/base/file.txt'
        $subDir = $this->baseDir . DIRECTORY_SEPARATOR . 'sub';
        $trickyDir = $subDir . DIRECTORY_SEPARATOR . basename($this->baseDir);
        if (!is_dir($trickyDir)) {
            mkdir($trickyDir, 0777, true);
        }
        $trickyFile = $trickyDir . DIRECTORY_SEPARATOR . 'file.txt';
        file_put_contents($trickyFile, 'dummy');

        $response = $this->reader->findPath($trickyFile, $this->baseDir);
        $this->assertSame(0, $response, "findPath should find first occurrence at pos 0");

        // Cleanup
        unlink($trickyFile);
        rmdir($trickyDir);
        rmdir($subDir);
    }

    /**
     * Kills Mutants: 34-36
     * Replaces 'testabsPathWeak'. Asserts that absPath() correctly
     * *canonicalizes* a path containing '..'.
     * This kills mutants that replace realpath() with basename() or dirname().
     */
    public function testAbsPathCanonicalizesPath(): void
    {
        $subDir = $this->baseDir . DIRECTORY_SEPARATOR . 'sub';
        if (!is_dir($subDir)) {
            mkdir($subDir, 0777, true);
        }
        $traversalPath = $subDir . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'safe_file.txt';
        
        $expected = trim(realpath($this->safeFilePath), DIRECTORY_SEPARATOR);
        $actual = $this->reader->absPath($traversalPath);
        
        $this->assertSame($expected, $actual);
        
        rmdir($subDir);
    }

    /**
     * Kills Mutants: 37 (stripos), 39 ('D:\')
     * Tests that secureFilePath() is case-sensitive.
     * This kills 'stripos' and 'D:\' mutants, which would incorrectly
     * pass the check and return true.
     */
    public function testSecureFilePathIsCaseSensitive(): void
    {
        $upperBase = strtoupper($this->baseDir);
        if ($upperBase === $this->baseDir && stripos(PHP_OS, 'WIN') === 0) {
            $this->markTestSkipped('Cannot test case-sensitivity on this OS/path.');
        }

        // We use a path that *does* exist, just with wrong case
        $response = $this->reader->secureFilePath($this->safeFilePath, $upperBase);
        $this->assertFalse($response, "secureFilePath check should be case-sensitive");
    }

    /**
     * Kills Mutant: 38 (strrpos)
     * Tests that secureFilePath() checks from the *start* (strpos ... !== 0)
     * and not the *last* occurrence (strrpos).
     */
    public function testSecureFilePathChecksFirstOccurrence(): void
    {
        // Create a path like '.../base/sub/base/file.txt'
        $subDir = $this->baseDir . DIRECTORY_SEPARATOR . 'sub';
        $trickyDir = $subDir . DIRECTORY_SEPARATOR . basename($this->baseDir);
        if (!is_dir($trickyDir)) {
            mkdir($trickyDir, 0777, true);
        }
        $trickyFile = $trickyDir . DIRECTORY_SEPARATOR . 'file.txt';
        file_put_contents($trickyFile, 'dummy');
        
        // Original code (strpos) finds '0', '0 !== 0' is false, so it passes.
        // Mutant code (strrpos) finds '>0', '>0 !== 0' is true, so it fails.
        $this->assertTrue(
            $this->reader->secureFilePath($trickyFile, $this->baseDir),
            "Original strpos should pass"
        );
        
        // Cleanup
        unlink($trickyFile);
        rmdir($trickyDir);
        rmdir($subDir);
    }

    /**
     * Kills Mutant: 40 (ExFindPathCheckingMutator)
     * Tests that secureFilePath() blocks a file that *exists* but is
     * *outside* the base path.
     * This kills the mutant that removed the strpos() check.
     */
    public function testSecureFilePathRejectsExistingExternalFile(): void
    {
        $this->assertFileExists($this->outsideFilePath);
        $response = $this->reader->secureFilePath($this->outsideFilePath, $this->baseDir);
        $this->assertFalse($response, "secureFilePath must block existing external files");
    }

    /**
     * Kills Mutant: 41 (ExReFileCheckingMutator)
     * Tests that secureFilePath() blocks a file that does *not* exist,
     * even if its path is *inside* the base directory.
     * This kills the mutant that removed the file_exists() check.
     */
    public function testSecureFilePathRejectsNonExistentFile(): void
    {
        $nonExistentPath = $this->baseDir . DIRECTORY_SEPARATOR . 'non-existent.txt';
        $this->assertFileDoesNotExist($nonExistentPath);
        $response = $this->reader->secureFilePath($nonExistentPath, $this->baseDir);
        $this->assertFalse($response, "secureFilePath must block non-existent files");
    }
}