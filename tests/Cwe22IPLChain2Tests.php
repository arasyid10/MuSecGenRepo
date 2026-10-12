<?php
use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe22IPLChain2Tests extends TestCase
{
    //GPT 5.0 Auto
 /* private VulnFileRead $reader;
    private string $base;
    private string $baseParent;

    protected function setUp(): void
    {
        $this->reader     = new VulnFileRead();
        $this->base       = (string) realpath(__DIR__ . '/../vulnerable_files');
        $this->assertNotFalse($this->base, 'Base vulnerable_files directory must exist for tests');
        $this->baseParent = dirname($this->base);
    }

    private function mkfile(string $path, string $data): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        file_put_contents($path, $data);
    }


    public function testRead_AllowsLegitFileInsideBase(): void
    {
        $file = $this->base . DIRECTORY_SEPARATOR . 'fixture_read_ok.txt';
        try {
            $this->mkfile($file, "SAFE_DATA");
            $result = $this->reader->read('fixture_read_ok.txt');
            $this->assertSame("SAFE_DATA", $result);
        } finally {
            @unlink($file);
        }
    }

    public function testRead_RejectsTraversalToParent(): void
    {
        $outside = $this->baseParent . DIRECTORY_SEPARATOR . 'outside_read.txt';
        try {
            $this->mkfile($outside, "SHOULD_NOT_LEAK");
            $attempt = $this->reader->read('..' . DIRECTORY_SEPARATOR . 'outside_read.txt');
            $this->assertSame('Access denied', $attempt);
        } finally {
            @unlink($outside);
        }
    }

   
    public function testIsValidSubPath_DeniesOutsidePath(): void
    {
        $outside = $this->baseParent . DIRECTORY_SEPARATOR . 'outsider.txt';
        try {
            $this->mkfile($outside, "INTRUDE");
            $this->assertFalse($this->reader->isValidSubPath($outside, $this->base));
        } finally {
            @unlink($outside);
        }
    }

    public function testIsValidSubPath_DeniesAbsoluteForeignPath(): void
    {
        $foreign = $this->baseParent . DIRECTORY_SEPARATOR . uniqid('foreign_', true) . '.txt';
        $this->assertFalse($this->reader->isValidSubPath($foreign, $this->base));
    }

        public function testFindPath_CorrectCase_ReturnsStrictZero(): void
    {
        $inBase = $this->base . DIRECTORY_SEPARATOR . 'find_ok.txt';
        try {
            $this->mkfile($inBase, 'x');
            $pos = $this->reader->findPath($inBase, $this->base);
            $this->assertSame(0, $pos);
        } finally {
            @unlink($inBase);
        }
    }

    public function testFindPath_WrongCaseBase_ReturnsFalse(): void
    {
        $inBase = $this->base . DIRECTORY_SEPARATOR . 'find_case.txt';
        try {
            $this->mkfile($inBase, 'y');
            $wrongCaseBase = strtoupper($this->base);
            $pos = $this->reader->findPath($inBase, $wrongCaseBase);
            $this->assertFalse($pos);
        } finally {
            @unlink($inBase);
        }
    }

       public function testAbsPath_NormalizesTraversalToExactRealpath(): void
    {
        $dir  = $this->base . DIRECTORY_SEPARATOR . 'abs_test';
        $sub  = $dir  . DIRECTORY_SEPARATOR . 'sub';
        $file = $dir  . DIRECTORY_SEPARATOR . 'file.txt';
        $pathWithTraversal = $sub . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'file.txt';
        try {
            $this->mkfile($file, 'data');
            if (!is_dir($sub)) { mkdir($sub, 0777, true); }
            $expected = trim((string) realpath($file), DIRECTORY_SEPARATOR);
            $actual   = $this->reader->absPath($pathWithTraversal);
            $this->assertSame($expected, $actual);
        } finally {
            @unlink($file);
            @rmdir($sub);
            @rmdir($dir);
        }
    }

    
    public function testSecureFilePath_RejectsCaseMismatchedBase(): void
    {
        $file = $this->base . DIRECTORY_SEPARATOR . 'case_guard.txt';
        try {
            $this->mkfile($file, 'ok');
            $wrongCaseBase = strtoupper($this->base);
            $this->assertFalse($this->reader->secureFilePath($file, $wrongCaseBase));
        } finally {
            @unlink($file);
        }
    }

    public function testSecureFilePath_EmptyBase_OriginalAcceptsButMutants38and39Reject(): void
    {
        $file = $this->base . DIRECTORY_SEPARATOR . 'emptybase_ok.txt';
        try {
            $this->mkfile($file, 'ok');
            $this->assertTrue($this->reader->secureFilePath($file, ''));
        } finally {
            @unlink($file);
        }
    }

    public function testSecureFilePath_RejectsReadableOutsideBase(): void
    {
        $outside = $this->baseParent . DIRECTORY_SEPARATOR . 'outside_secure.txt';
        try {
            $this->mkfile($outside, 'leak');
            $this->assertFalse($this->reader->secureFilePath($outside, $this->base));
        } finally {
            @unlink($outside);
        }
    }

    public function testSecureFilePath_RejectsNonexistentFile(): void
    {
        $fake = $this->base . DIRECTORY_SEPARATOR . ('nonexistent_' . uniqid('', true) . '.txt');
        $this->assertFalse($this->reader->secureFilePath($fake, $this->base));
    }*/

        //QWEN3-Max
  /*  private $reader;
    private $baseDir;

    protected function setUp(): void
    {
        $this->reader = new VulnFileRead();
        $this->baseDir = realpath(__DIR__ . '/../vulnerable_files');
        // Ensure predictable test files
        file_put_contents($this->baseDir . '/safe.txt', 'SAFE_CONTENT');
        file_put_contents($this->baseDir . '/secret.txt', 'SECRET_DATA');
    }

    protected function tearDown(): void
    {
        @unlink($this->baseDir . '/safe.txt');
        @unlink($this->baseDir . '/secret.txt');
    }

    
    public function testValidFileAccessSucceeds(): void
    {
        $result = $this->reader->read('safe.txt');
        $this->assertStringContainsString('SAFE_CONTENT', $result);
    }

   
    public function testPathTraversalIsDenied(): void
    {
        // Attempt deep traversal to a common project file outside base
        $result = $this->reader->read('../../../../composer.json');
        $this->assertSame('Access denied', $result);
    }

    
    public function testHelperMethodsEnforceBaseRestriction(): void
    {
        $base = __DIR__;
        $validPath = __DIR__ . '/legit.txt';
        $traversalPath = __DIR__ . "\\..\\..\\..\\..\\..\\..\\..\\..\\pwdss.txt";

        // Test isValidSubPath
        $this->assertTrue($this->reader->isValidSubPath($validPath, $base));
        $this->assertFalse($this->reader->isValidSubPath($traversalPath, $base));

        // Test secureFilePath (note: it expects basePath with trailing separator)
        $basePathWithSep = $base ;
        $this->assertTrue($this->reader->secureFilePath($validPath, $basePathWithSep));
        $this->assertFalse($this->reader->secureFilePath($traversalPath, $basePathWithSep));
    }

    
    public function testPathHelpersReturnCorrectCanonicalValues(): void
    {
        $base = $this->baseDir;
        $validFile = $base . '/safe.txt';
        $traversalFile = __DIR__ . '/../vulnerable_files/../../../autoexec.bat';

        // findPath must return int(0) for valid base match
        $this->assertSame(0, $this->reader->findPath($validFile, $base));
        // and not 0 for traversal
        $this->assertNotSame(0, $this->reader->findPath($traversalFile, $base));

        // absPath must return full normalized real path
        $expected = trim(realpath($validFile), DIRECTORY_SEPARATOR);
        $this->assertSame($expected, $this->reader->absPath($validFile));
    }*/
    
        //CLAUDE 4.5 Sonnet
    private VulnFileRead $reader;  
    private string $baseDir;  
    private string $parentDir;  
  
    protected function setUp(): void  
    {  
        $this->reader = new VulnFileRead();  
        $this->baseDir = __DIR__ . '/../vulnerable_files';  
        $this->parentDir = dirname($this->baseDir);  
          
        if (!file_exists($this->baseDir)) {  
            mkdir($this->baseDir, 0777, true);  
        }  
    }  
  
    protected function tearDown(): void  
    {  
        // Cleanup test files  
        foreach (glob($this->baseDir . '/*') as $file) {  
            if (is_file($file)) @unlink($file);  
        }  
        foreach (glob($this->parentDir . '/escape_*.txt') as $file) {  
            @unlink($file);  
        }  
    }  
  
    // ========================================================================  
    // TEST 1: Kill Mutants 1-3, 8-10, 34-36 (Canonicalization Removal)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutants 1, 2, 3, 8, 9, 10, 34, 35, 36  
     *   
     * Mutant IDs:  
     * - 6f32b4d0411e96dc8f8246fac2b62198 (realpath→basename, line 10)  
     * - a835b77d9d02cfe5bf67706eef697213 (realpath→dirname, line 10)  
     * - 74ec93782823e9a58285e40d08cf4268 (realpath→pathinfo, line 10)  
     * - f3d429ba1809c48f57d80cb8418c80fa (realpath→basename, line 13)  
     * - 7774318b2bbd58c7cfe65cae5ffbb7ae (realpath→dirname, line 13)  
     * - bbdacbd1d724b34e4ca9847b806b7638 (realpath→pathinfo, line 13)  
     * - a7d440a42e1add12b3d7b0e959a5885a (realpath→basename, line 36)  
     * - 8d247869227e33af2982d66bf790ee37 (realpath→dirname, line 36)  
     * - 9ae3bdd15155aeb1ff2d68ac7c76ad6a (realpath→pathinfo, line 36)  
     *   
     * Strategy: Test legitimate file access  
     * - Original: realpath() canonicalizes path → str_starts_with() passes → file accessible  
     * - Mutant: basename/dirname/pathinfo breaks canonicalization → check fails → access denied  
     *   
     * @test  
     */  
    public function testLegitimateFileAccessRequiresCanonicalization(): void  
    {  
        // Create legitimate file  
        $filename = 'legitimate_file.txt';  
        file_put_contents($this->baseDir . '/' . $filename, 'SAFE_CONTENT_12345');  
  
        // Test read() method (kills mutants 1-3, 8-10)  
        $result = $this->reader->read($filename);  
          
        $this->assertStringContainsString(  
            'SAFE_CONTENT_12345',  
            $result,  
            'FAILED: Mutants 1-3, 8-10 survived - legitimate file was blocked'  
        );  
  
        // Test absPath() method (kills mutants 34-36)  
        $pathWithTraversal = $this->baseDir . '/../vulnerable_files/' . $filename;  
        $absResult = $this->reader->absPath($pathWithTraversal);  
          
        $this->assertStringNotContainsString(  
            '..',  
            $absResult,  
            'FAILED: Mutants 34-36 survived - traversal sequence not resolved'  
        );  
          
        $this->assertNotEmpty(  
            $absResult,  
            'FAILED: Mutants 34-36 survived - absPath returned empty/invalid result'  
        );  
    }  
  
    // ========================================================================  
    // TEST 2: Kill Mutants 4-7, 11-14 (Hardcoded Path Injection)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutants 4, 5, 6, 7, 11, 12, 13, 14  
     *   
     * Mutant IDs:  
     * - 772f7a976738aee52d7b251917c5789d (hardcoded path, line 10)  
     * - 1b631d463498d97e12d2805cae271842 (hardcoded path, line 10)  
     * - ccfce32fe4e8c00796ff7fbfd1fa0ddd (hardcoded path, line 10)  
     * - 5a3c1515b272ced3dc37c138e9f8ef1a (hardcoded path, line 10)  
     * - 1f47e61a5650e58630b747caec3ceeea (hardcoded base, line 13)  
     * - ed29142635128136617f4879b6db9916 (hardcoded base, line 13)  
     * - 06acc8db16e4522e8ade4556c8f10177 (hardcoded base, line 13)  
     * - 2dbd99c223aaa59b0d984375fb69dab2 (hardcoded base, line 13)  
     *   
     * Strategy: Test input-output correlation  
     * - Original: Different inputs → different outputs  
     * - Mutant: Hardcoded path → same output for all inputs  
     *   
     * @test  
     */  
    public function testDifferentInputsProduceDifferentOutputs(): void  
    {  
        // Create two files with unique content  
        file_put_contents($this->baseDir . '/file_alpha.txt', 'CONTENT_ALPHA_UNIQUE');  
        file_put_contents($this->baseDir . '/file_beta.txt', 'CONTENT_BETA_UNIQUE');  
  
        $resultAlpha = $this->reader->read('file_alpha.txt');  
        $resultBeta = $this->reader->read('file_beta.txt');  
  
        // Kill condition: Results must be different  
        $this->assertNotSame(  
            $resultAlpha,  
            $resultBeta,  
            'FAILED: Mutants 4-7, 11-14 survived - hardcoded path returned same output'  
        );  
  
        // Verify correct content mapping  
        $this->assertStringContainsString('CONTENT_ALPHA_UNIQUE', $resultAlpha);  
        $this->assertStringContainsString('CONTENT_BETA_UNIQUE', $resultBeta);  
    }  
  
    // ========================================================================  
    // TEST 3: Kill Mutants 15-16, 21, 31, 39 (Drive Letter Injection)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutants 15, 16, 21, 31, 39  
     *   
     * Mutant IDs:  
     * - a7edfe7f1c47f9e369e97eeee1f4150c (C:\\ injection, line 13)  
     * - c1eca2db17d107cc2fa095ca54ba5233 (D:\\ injection, line 13)  
     * - d2f13eb1ca0f033520041e1016a56aaf (D:\\ injection, line 27)  
     * - 4e0f1c4448f0b6b36922115f102ac614 (D:\\ injection, line 32)  
     * - e4dfb2cb4ae4bf4caca1fb99554f82ee (D:\\ injection, line 44)  
     *   
     * Strategy: Test that files outside base are blocked  
     * - Original: Checks against actual base path → outside files blocked  
     * - Mutant: Checks against 'C:\\' or 'D:\\' → any file on drive passes  
     *   
     * @test  
     */  
    public function testOutsideFilesAreBlocked(): void  
    {  
        // Create file outside base directory  
        $outsideFile = 'escape_outside.txt';  
        file_put_contents($this->parentDir . '/' . $outsideFile, 'ESCAPED_CONTENT');  
  
        // Test read() method (kills mutants 15-16)  
        $result = $this->reader->read('../' . $outsideFile);  
          
        $this->assertSame(  
            'Access denied',  
            $result,  
            'FAILED: Mutants 15-16 survived - drive letter injection allowed traversal'  
        );  
  
        // Test isValidSubPath() method (kills mutant 21)  
        $outsidePath = $this->parentDir . '/' . $outsideFile;  
        $isValid = $this->reader->isValidSubPath($outsidePath, $this->baseDir);  
          
        $this->assertFalse(  
            $isValid,  
            'FAILED: Mutant 21 survived - drive letter injection in isValidSubPath'  
        );  
  
        // Test findPath() method (kills mutant 31)  
        $findResult = $this->reader->findPath($outsidePath, $this->baseDir);  
          
        $this->assertNotSame(  
            0,  
            $findResult,  
            'FAILED: Mutant 31 survived - drive letter injection in findPath'  
        );  
  
        // Test secureFilePath() method (kills mutant 39)  
        $secureResult = $this->reader->secureFilePath($outsidePath, $this->baseDir);  
          
        $this->assertFalse(  
            $secureResult,  
            'FAILED: Mutant 39 survived - drive letter injection in secureFilePath'  
        );  
  
        @unlink($this->parentDir . '/' . $outsideFile);  
    }  
  
    // ========================================================================  
    // TEST 4: Kill Mutants 17-20 (isValidSubPath Canonicalization)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutants 17, 18, 19, 20  
     *   
     * Mutant IDs:  
     * - c14be317bd3b3c4926e152f100cf4d82 (realpath→dirname, line 22)  
     * - f7fb5f746a8af766f5abea30deb6d200 (realpath→pathinfo, line 22)  
     * - f7c65af39c9c9e625fa24420613ac86b (realpath→dirname, line 23)  
     * - ff4eb58c2554d94d1cec7a42c1f701f3 (realpath→pathinfo, line 23)  
     *   
     * Strategy: Test traversal path rejection  
     * - Original: realpath() resolves ".." → detects escape → returns false  
     * - Mutant: dirname/pathinfo doesn't resolve ".." → might pass incorrectly  
     *   
     * @test  
     */  
    public function testIsValidSubPathRejectsTraversal(): void  
    {  
        // Create file outside base  
        file_put_contents($this->parentDir . '/escape_traversal.txt', 'ESCAPED');  
  
        // Test with traversal path  
        $traversalPath = $this->baseDir . '/../escape_traversal.txt';  
        $result = $this->reader->isValidSubPath($traversalPath, $this->baseDir);  
  
        $this->assertFalse(  
            $result,  
            'FAILED: Mutants 17-20 survived - traversal not detected without canonicalization'  
        );  
  
        // Also test that legitimate path still works (catches dirname/pathinfo breaking logic)  
        $legitPath = $this->baseDir . '/legit.txt';  
        file_put_contents($legitPath, 'LEGIT');  
          
        $legitResult = $this->reader->isValidSubPath($legitPath, $this->baseDir);  
          
        $this->assertTrue(  
            $legitResult,  
            'FAILED: Mutants 17-20 survived - legitimate path incorrectly rejected'  
        );  
  
        @unlink($this->parentDir . '/escape_traversal.txt');  
    }  
  
    // ========================================================================  
    // TEST 5: Kill Mutants 22, 32, 33, 40, 41 (Always Return True/False)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutants 22, 32, 33, 40, 41  
     *   
     * Mutant IDs:  
     * - f1e09b9ba63ee580db081cf5780d645c (always return true, line 27)  
     * - b96a03dcc058c98839a6e564a4c13741 (always return 0, line 32)  
     * - 6d8f3db1c10882af81dd2cc5ca5f16b7 (always return true, line 32)  
     * - 7ec52fda0c94bdd76ff427f1f754e0aa (remove prefix check, line 44)  
     * - 06abc8712f0ba96c19999fcea62f7acc (remove file checks, line 47)  
     *   
     * Strategy: Test with invalid/non-existent paths  
     * - Original: Returns false for invalid paths  
     * - Mutant: Always returns true → accepts invalid paths  
     *   
     * @test  
     */  
    public function testInvalidPathsAreRejected(): void  
    {  
        // Test isValidSubPath with completely invalid path (kills mutant 22)  
        $invalidPath = '/completely/invalid/path/does/not/exist';  
        $result1 = $this->reader->isValidSubPath($invalidPath, $this->baseDir);  
          
        $this->assertFalse(  
            $result1,  
            'FAILED: Mutant 22 survived - isValidSubPath always returns true'  
        );  
  
        // Test findPath with wrong path (kills mutants 32, 33)  
        $wrongPath = 'C:\\Windows\\System32\\config\\SAM';  
        $result2 = $this->reader->findPath($wrongPath, $this->baseDir);  
          
        $this->assertFalse(  
            $result2,  
            'FAILED: Mutants 32-33 survived - findPath always returns 0/true'  
        );  
  
        // Test secureFilePath with outside file (kills mutant 40)  
        file_put_contents($this->parentDir . '/escape_secure.txt', 'ESCAPED');  
        $outsidePath = $this->parentDir . '/escape_secure.txt';  
        $result3 = $this->reader->secureFilePath($outsidePath, $this->baseDir);  
          
        $this->assertFalse(  
            $result3,  
            'FAILED: Mutant 40 survived - prefix check removed'  
        );  
  
        // Test secureFilePath with non-existent file (kills mutant 41)  
        $nonExistent = $this->baseDir . '/does_not_exist_xyz.txt';  
        $this->assertFileDoesNotExist($nonExistent);  
          
        $result4 = $this->reader->secureFilePath($nonExistent, $this->baseDir);  
          
        $this->assertFalse(  
            $result4,  
            'FAILED: Mutant 41 survived - file existence check removed'  
        );  
  
        @unlink($this->parentDir . '/escape_secure.txt');  
    }  
  
    // ========================================================================  
    // TEST 6: Kill Mutants 23-24 (findPath Canonicalization)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutants 23, 24  
     *   
     * Mutant IDs:  
     * - 5800703429f6f96586031f88667d994e (realpath→dirname, line 32)  
     * - 57bfa83ac74d7898b911c8c38cbd8d78 (realpath→pathinfo, line 32)  
     *   
     * Strategy: Test findPath with traversal  
     * - Original: realpath() resolves ".." → correct position check  
     * - Mutant: dirname/pathinfo doesn't resolve → wrong position  
     *   
     * @test  
     */  
    public function testFindPathRequiresCanonicalization(): void  
    {  
        // Create file outside base  
        file_put_contents($this->parentDir . '/escape_find.txt', 'ESCAPED');  
  
        // Path with ".." that escapes  
        $escapePath = $this->baseDir . '/../escape_find.txt';  
        $result = $this->reader->findPath($escapePath, $this->baseDir);  
  
        // Should NOT return 0 (not found at position 0)  
        $this->assertNotSame(  
            0,  
            $result,  
            'FAILED: Mutants 23-24 survived - non-canonical path incorrectly matched'  
        );  
  
        @unlink($this->parentDir . '/escape_find.txt');  
    }  
  
    // ========================================================================  
    // TEST 7: Kill Mutant 25 (strpos → stripos, Case Insensitive)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutant 25  
     *   
     * Mutant ID: 8e1b051455d2240e92fc3771804f6a02  
     *   
     * Strategy: Test case-sensitive path matching  
     * - Original: strpos() is case-sensitive → different case fails  
     * - Mutant: stripos() is case-insensitive → different case passes  
     *   
     * @test  
     */  
    public function testFindPathIsCaseSensitive(): void  
    {  
        // Create file with specific case  
        $filePath = $this->baseDir . '/CaseSensitive.txt';  
        file_put_contents($filePath, 'CONTENT');  
  
        // Use different case for base path  
        $baseLower = strtolower($this->baseDir);  
        $result = $this->reader->findPath($filePath, $baseLower);  
  
        // Case-sensitive match should fail  
        $this->assertNotSame(  
            0,  
            $result,  
            'FAILED: Mutant 25 survived - stripos allowed case-insensitive bypass'  
        );  
    }  
  
    // ========================================================================  
    // TEST 8: Kill Mutants 26-30 (Wrong String Function Return Types)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutants 26, 27, 28, 29, 30  
     *   
     * Mutant IDs:  
     * - 374d3615b37eda4354894ab07a90aa35 (strpos→str_contains, line 32)  
     * - a7652c44ba21c720a516855105248918 (strpos→str_starts_with, line 32)  
     * - ae8bf332a9efd75df25ad3c08a1f91c1 (strpos→strrpos, line 32)  
     * - 32d2514cefdc5af98e344c4bd61b3325 (strpos→strstr, line 32)  
     * - 2a59e46ab70b0671067d3283358a05e9 (strpos→strpbrk, line 32)  
     *   
     * Strategy: Test return type/value  
     * - Original: strpos() returns int 0 for match at start  
     * - Mutant: str_contains/str_starts_with return bool, strstr/strpbrk return string  
     *   
     * @test  
     */  
    public function testFindPathReturnsCorrectType(): void  
    {  
        // Create legitimate file  
        $legitPath = __DIR__ . '/legit.txt';  
        file_put_contents($legitPath, 'CONTENT');  
  
        $result = $this->reader->findPath($legitPath, __DIR__);  
  
        // Must return exactly 0 (integer) for match at start  
        $this->assertSame(  
            0,  
            $result,  
            'FAILED: Mutants 26-30 survived - wrong return type/value from string function'  
        );  
  
        // Additional type check  
        $this->assertIsInt(  
            $result,  
            'FAILED: Mutants 26-30 survived - return type is not integer'  
        );  
    }  
  
    // ========================================================================  
    // TEST 9: Kill Mutant 37 (secureFilePath strpos → stripos)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutant 37  
     *   
     * Mutant ID: 557855c3029acf45272ebfeeb5f87b46  
     *   
     * Strategy: Test case-sensitive path matching in secureFilePath  
     * - Original: strpos() is case-sensitive  
     * - Mutant: stripos() is case-insensitive  
     *   
     * @test  
     */  
    public function testSecureFilePathIsCaseSensitive(): void  
    {  
        // Create file with specific case  
        $filePath = $this->baseDir . '/test_case.txt';  
        file_put_contents($filePath, 'CONTENT');  
  
        // Use different case for base  
        $baseDifferentCase = strtoupper($this->baseDir);  
        $result = $this->reader->secureFilePath($filePath, $baseDifferentCase);  
  
        // Case-sensitive match should fail  
        $this->assertFalse(  
            $result,  
            'FAILED: Mutant 37 survived - stripos allowed case-insensitive bypass'  
        );  
    }  
  
    // ========================================================================  
    // TEST 10: Kill Mutant 38 (strpos → strrpos, Last Occurrence)  
    // ========================================================================  
  
    /**  
     * KILLS: Mutant 38  
     *   
     * Mutant ID: 9d9481b3d1c436c6000c7b51a7317867  
     *   
     * Strategy: Test prefix matching (not substring matching)  
     * - Original: strpos() finds first occurrence → checks if at position 0  
     * - Mutant: strrpos() finds last occurrence → wrong position check  
     *   
     * @test  
     */  
    public function testSecureFilePathChecksPrefix(): void  
    {  
        // Create legitimate file in base  
        $legitPath = $this->baseDir . '/legit.txt';  
        file_put_contents($legitPath, 'CONTENT');  
  
        // Test legitimate file (should pass)  
        $result1 = $this->reader->secureFilePath($legitPath, $this->baseDir);  
          
        $this->assertTrue(  
            $result1,  
            'FAILED: Mutant 38 survived - legitimate file rejected'  
        );  
  
        // Create a malicious path where base appears NOT at position 0  
        // This would fail with strrpos if base appears later  
        $maliciousPath = '/evil/prefix' . $this->baseDir . '/file.txt';  
        $result2 = $this->reader->secureFilePath($maliciousPath, $this->baseDir);  
  
        $this->assertFalse(  
            $result2,  
            'FAILED: Mutant 38 survived - strrpos allowed non-prefix match'  
        );  
    }  
  
    // ========================================================================  
    // TEST 11: Comprehensive Path Traversal Security Test  
    // ========================================================================  
  
    /**  
     * Comprehensive security test for path traversal attacks  
     * Ensures all mutants related to traversal are killed  
     *   
     * @test  
     */  
    public function testComprehensivePathTraversalBlocking(): void  
    {  
        $traversalPayloads = [  
            '../../../etc/passwd',  
            '..\\..\\..\\Windows\\System32\\config\\SAM',  
            '....//....//....//etc/passwd',  
            '..//..//..//etc//passwd',  
            '..%2F..%2F..%2Fetc%2Fpasswd',  
        ];  
  
        foreach ($traversalPayloads as $payload) {  
            $result = $this->reader->read($payload);  
              
            $this->assertSame(  
                'Access denied',  
                $result,  
                "FAILED: Traversal payload '$payload' was not blocked"  
            );  
        }  
    }  
  
    // ========================================================================  
    // TEST 12: Legitimate File Access (Positive Test)  
    // ========================================================================  
  
    /**  
     * Positive test: Ensure legitimate files are accessible  
     * Prevents false positives from overly restrictive mutations  
     *   
     * @test  
     */  
    public function testLegitimateFilesAreAccessible(): void  
    {  
        // Create multiple legitimate files  
        $files = [  
            'document.txt' => 'Document content',  
            'data.json' => '{"key":"value"}',  
            'config.ini' => '[section]\nkey=value',  
        ];  
  
        foreach ($files as $filename => $content) {  
            file_put_contents($this->baseDir . '/' . $filename, $content);  
              
            $result = $this->reader->read($filename);  
              
            $this->assertStringContainsString(  
                $content,  
                $result,  
                "FAILED: Legitimate file '$filename' was not accessible"  
            );  
        }  
    }
}
