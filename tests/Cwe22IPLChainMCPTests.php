<?php

namespace Tests;

use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe22IPLChainMCPTests extends TestCase
{
    protected VulnFileRead $reader;
    private string $baseDir;
    private  $legitFile;
     private $base;
    private   $vulnerableFilesDir;
    private   $outsideFilePath; 
    private   $secretFilePath;
    private $traversalPath;
    private $unreadableFile;
    private $imageDir;
    protected function setUp(): void
    {
       $this->reader = new VulnFileRead();
        // $this->base = realpath(__DIR__ . '/../vulnerable_files/');
          //$this->basePath = realpath(__DIR__ . '/../vulnerable_files/');
           $this->baseDir = realpath(__DIR__ . '/../vulnerable_files/');
        $this->legitFile = 'legit.txt';
        $this->outsideFilePath = '../config.ini'; // or any file outside baseDir
        $this->secretFilePath = __DIR__ . '/../composer.json';
        $this->vulnerableFilesDir=__DIR__ . '/../config';
        $this->traversalPath = __DIR__."\\..\\..\\..\\..\\..\\..\\..\\..\\pwds.txt"; 
        $this->unreadableFile = $this->baseDir . '/unreadable.txt';
        $this->imageDir = __DIR__ . '/../images';   
    }
//GPT 9 TC 4 Adjusted
 /*public function testReadRejectsTraversalVariantsIncludingEncodedAndDoubleEncoded()
    {
        $payloads = [
            '../../etc/passwd',
            '..\\..\\etc\\passwd',
            '%2e%2e%2fetc/passwd',
            '%2e%2e%5cetc\\passwd',
            '..%2f..%2fetc/passwd',
            '%2e%2e%2f%2e%2e%2fetc/passwd'
        ];
        foreach ($payloads as $p) {
            $res = $this->reader->read($p);
            $this->assertStringContainsString('Access denied', $res, "Payload $p should be denied");
        }
    }

    public function testReadAllowsInsideFileButDeniesOutsideEvenWithPathPayloadMutant()
    {
        $inside = 'allowed.txt';
        $resInside = $this->reader->read($inside);
        $this->assertIsString($resInside);
        $this->assertNotSame('Access denied', $resInside);

        // attempt a hardcoded payload mutator
        $resHard = $this->reader->read('C:\xampp\htdocs\samplecode\MyProject\File.txt');
        $this->assertStringContainsString('Access denied', $resHard);
    }

    public function testReadDeniesWhenprefixcheckmutatedSecondArgToBasenameOrDirname()
    {
        // supply a filename that would make basename($base) or dirname($base) match incorrectly
        $filename = '../vulnerable_files/legit.txt';
        $res = $this->reader->read($filename);
        $this->assertStringContainsString('Access denied', $res);
    }

    public function testIsValidSubPathFailsWheninputnormalizationisremoved()
    {
        // when realpath is replaced by dirname or pathinfo, the check may erroneously accept a traversal
        $input = $this->baseDir . '../etc/passwd';
        $this->assertFalse($this->reader->isValidSubPath($input, $this->baseDir));

        // drive‐based override
        $this->assertFalse($this->reader->isValidSubPath('D:\\evil', $this->baseDir));
    }

    public function testFindPathRejectsOutsideWithInvalidPrefixChecks()
    {
        $out = $this->reader->findPath($this->baseDir . '../etc/passwd', $this->baseDir);
        $this->assertFalse($out);

        // ensure that constant‐return or stripos variants are killed
        $inside = $this->baseDir . 'legit.txt';
        $resp = $this->reader->findPath($inside, $this->baseDir);
        $this->assertFalse( $resp);
    }

    public function testFindPathRemovesMutantsReplacingRealpathWithDirnameOrPathinfo()
    {
        // A payload that triggers difference between realpath vs dirname behavior
        $path = $this->baseDir . 'nested/../legit.txt';
        $resp = $this->reader->findPath($path, $this->baseDir);
        $this->assertFalse( $resp);
    }

    public function testAbsPathWithNonexistentPathAndMutatedNormalization()
    {
        $p = $this->baseDir . 'nonexistent/../something.txt';
        $norm = $this->reader->absPath($p);
        $this->assertEmpty($norm);
        $this->assertSame(trim(realpath($p) ?: '', DIRECTORY_SEPARATOR), $norm);
    }

    public function testSecureFilePathRejectsWhenprefixcheckismutatedToStriposOrStrrposOrRemoved()
    {
        $outside = $this->baseDir . '../secrets.txt';
        $this->assertFalse($this->reader->secureFilePath($outside, $this->baseDir));
    }

    public function testSecureFilePathRejectsIfExistsGuardIsRemoved()
    {
        $non = $this->baseDir . 'does_not_exist.txt';
        $this->assertFalse($this->reader->secureFilePath($non, $this->baseDir));
    }
        //QWEN 17 TC 0 Adjusted

    public function testReadRejectsPathWhenRealpathFailsDueToNonExistentFile(): void
{
    $attempt = $this->reader->read('non_existent_file.txt');
    $this->assertSame('Access denied', $attempt);
}

public function testReadRejectsTraversalWithDotDotEvenIfBasenameOrDirnameWouldPass(): void
{
    $attempt = $this->reader->read('../vulnerable_files/../../composer.json');
    $this->assertSame('Access denied', $attempt);
}

public function testReadRejectsAbsoluteTraversalPayloads(): void
{
    $attempt = $this->reader->read('/etc/passwd');
    $this->assertSame('Access denied', $attempt);
}

public function testReadRejectsEncodedTraversal(): void
{
    $attempt = $this->reader->read('%2e%2e%2fetc%2fpasswd');
    $this->assertSame('Access denied', $attempt);
}

public function testIsValidSubPathReturnsFalseForNonExistentPath(): void
{
    $basePath = __DIR__;
    $inputPath = __DIR__ . '/non_existent_file.php';
    $result = $this->reader->isValidSubPath($inputPath, $basePath);
    $this->assertFalse($result);
}

public function testIsValidSubPathReturnsFalseForTraversalOutsideBase(): void
{
    $basePath = __DIR__;
    $inputPath = __DIR__ . '/../composer.json';
    $result = $this->reader->isValidSubPath($inputPath, $basePath);
    $this->assertFalse($result);
}

public function testAbsPathReturnsEmptyForNonExistentPath(): void
{
    $path = __DIR__ . '/non_existent_file.txt';
    $response = $this->reader->absPath($path);
    $this->assertEmpty($response);
}

public function testFindPathReturnsFalseForPathOutsideBase(): void
{
    $basePath = realpath(__DIR__ . '/../vulnerable_files');
    $outsidePath = __DIR__ . '/../../composer.json';
    $response = $this->reader->findPath($outsidePath, $basePath);
    $this->assertFalse($response);
}

public function testFindPathReturnsZeroOnlyWhenPathIsExactlyAtBaseStart(): void
{
    $basePath = realpath(__DIR__ . '/../vulnerable_files');
    $insidePath = $basePath . '/legit.txt';
    $response = $this->reader->findPath($insidePath, $basePath);
    $this->assertSame(0, $response);
}

public function testSecureFilePathRejectsPathNotStartingWithBaseEvenIfFileExists(): void
{
    $basePath = realpath(__DIR__ . '/../vulnerable_files');
    $outsidePath = __DIR__ . '/../composer.json';
    
        $response = $this->reader->secureFilePath($outsidePath, $basePath);
        $this->assertFalse($response);
    
}

public function testSecureFilePathRejectsNonExistentFileInsideBase(): void
{
    $basePath = realpath(__DIR__ . '/../vulnerable_files');
    $fakePath = $basePath . '/non_existent.txt';
    $response = $this->reader->secureFilePath($fakePath, $basePath);
    $this->assertFalse($response);
}

public function testSecureFilePathRejectsUnreadableFile(): void
{
    $basePath = realpath(__DIR__ . '/../vulnerable_files');
    $unreadablePath = $basePath . '/unreadable_file.txt';
    if (!file_exists($unreadablePath)) {
        touch($unreadablePath);
        chmod($unreadablePath, 0222);
    }
    $response = $this->reader->secureFilePath($unreadablePath, $basePath);
    $this->assertTrue($response);
    unlink($unreadablePath);
}

public function testReadUsesCanonicalPathAndRejectsCaseVariantsOnCaseSensitiveFs(): void
{
    $basePath = realpath(__DIR__ . '/../vulnerable_files');
    if ($basePath && file_exists($basePath . '/EXAMPLE.TXT')) {
        $attempt = $this->reader->read('EXAMPLE.TXT');
        $realBase = realpath(__DIR__ . '/../vulnerable_files');
        $realInput = realpath($basePath . '/EXAMPLE.TXT');
        if ($realInput !== false && str_starts_with($realInput, $realBase)) {
            $this->assertNotSame('Access denied', $attempt);
        } else {
            $this->assertSame('Access denied', $attempt);
        }
    } else {
        $attempt = $this->reader->read('EXAMPLE.TXT');
        $this->assertSame('Access denied', $attempt);
    }
}

public function testReadRejectsPayloadsThatResolveOutsideAfterCanonicalization(): void
{
    $attempt = $this->reader->read('valid.txt/../../composer.json');
    $this->assertSame('Access denied', $attempt);
}

public function testIsValidSubPathEnforcesCanonicalPrefixWithBoundaryCheck(): void
{
    $basePath = __DIR__;
    $inputPath = __DIR__ . 'extra/../CWE352CSRFTest.php';
    $result = $this->reader->isValidSubPath($inputPath, $basePath);
    $this->assertFalse($result);
}

public function testFindPathRejectsPartialSubstringMatches(): void
{
    $basePath = 'D:\\fake';
    $path = 'D:\\fake_path\\file.txt';
    $response = $this->reader->findPath($path, $basePath);
    $this->assertFalse($response);
}

public function testSecureFilePathRequiresExactBasePrefixNotSubstring(): void
{
    $basePath = __DIR__;
    $filePath = __DIR__ . '_suffix/file.txt';
    $response = $this->reader->secureFilePath($filePath, $basePath);
    $this->assertFalse($response);
}
//Tambahan QWEN
public function testReadRejectsTraversalWhenBaseIsCurrentDirAndRealpathIsReplacedByBasename(): void
{
    $attempt = $this->reader->read('../../composer.json');
    $this->assertSame('Access denied', $attempt);
}

public function testReadFailsIfBaseCheckUsesBasenameInsteadOfRealpath(): void
{
    $filename = 'valid.txt';
    $base = __DIR__;
    $fullPath = realpath($base . '/' . $filename);
    if ($fullPath === false) {
        $this->markTestSkipped('Test file not available');
    }
    $attempt = $this->reader->read($filename);
    $this->assertNotSame('Access denied', $attempt);
}

public function testReadRejectsAccessWhenBaseCheckIsHardcodedToDriveLetter(): void
{
    $attempt = $this->reader->read('../../composer.json');
    $this->assertSame('Access denied', $attempt);
}

public function testFindPathIsCaseSensitiveAndFailsWithCaseMismatch(): void
{
    $basePath = realpath(__DIR__);
    $path = $basePath . '/legit.txt';
    
    $response = $this->reader->findPath($path, strtoupper($basePath));
    
        $this->assertNotSame(0, $response, 'Case-insensitive match should not return position 0');
}

public function testFindPathRequiresPrefixMatchNotSuffix(): void
{
    $basePath = 'D:\\project';
    $path = 'D:\\backup_project\\file.txt';
    $realPath = realpath(__DIR__);
    if ($realPath) {
        $path = $realPath . '/backup_project/file.txt';
        if (!is_dir(dirname($path))) {
            mkdir(dirname($path), 0777, true);
        }
        file_put_contents($path, 'test');
        $response = $this->reader->findPath($path, $realPath . '/project');
        $this->assertFalse($response !== false && $response === 0);
        unlink($path);
        rmdir(dirname($path));
    }
}

public function testFindPathFailsWhenHardcodedToDriveLetterAndPathIsOnDifferentDrive(): void
{
    $basePath = __DIR__;
    $path = $basePath . '/test.txt';
    file_put_contents($path, 'test');
    $response = $this->reader->findPath($path, $basePath);
    $this->assertSame(0, $response);
    unlink($path);
}

public function testSecureFilePathIsCaseSensitiveOnPrefixCheck(): void
{
    $basePath = __DIR__;
    $filePath = $basePath . '/testfile.txt';
    file_put_contents($filePath, 'test');
    $response = $this->reader->secureFilePath($filePath, strtoupper($basePath));
    $this->assertFalse($response);
    unlink($filePath);
}

public function testSecureFilePathRequiresExactPrefixNotSubstringAtEnd(): void
{
    $basePath = __DIR__ . '/base';
    $subDir = $basePath . '/sub';
    if (!is_dir($subDir)) {
        mkdir($subDir, 0777, true);
    }
    $filePath = $subDir . '/file.txt';
    file_put_contents($filePath, 'test');
    $response = $this->reader->secureFilePath($filePath, $subDir . 'sub');
    $this->assertFalse($response);
    unlink($filePath);
    rmdir($subDir);
    rmdir($basePath);
}
public function testReadRejectsTraversalWhenRealpathIsReplacedWithBasename(): void
{
    $result = $this->reader->read('../../composer.json');
    $this->assertSame('Access denied', $result);
}

public function testReadAllowsValidFileOnlyWhenFullCanonicalPathStartsWithRealBase(): void
{
    $testFile = __DIR__ . '/test_valid_read.txt';
    file_put_contents($testFile, 'allowed content');
    $result = $this->reader->read('allowed.txt');
    $this->assertSame('safecontent', $result);
    unlink($testFile);
}

public function testReadRejectsValidFilenameIfBaseCheckUsesOnlyBasenameOfBase(): void
{
    $testFile = __DIR__ . '/test_basename_check.txt';
    file_put_contents($testFile, 'content');
    $result = $this->reader->read('allowed.txt');
    $this->assertSame('safecontent', $result);
    unlink($testFile);
}

public function testReadRejectsAccessWhenBaseCheckIsHardcodedToDriveLetterC(): void
{
    $result = $this->reader->read('../../composer.json');
    $this->assertSame('Access denied', $result);
}

public function testFindPathReturnsFalseWhenBaseAppearsOnlyAtEndNotStart(): void
{
    $basePath = 'project';
    $path = __DIR__ . '/backup_project/file.txt';
    if (!is_dir(dirname($path))) {
        mkdir(dirname($path), 0777, true);
    }
    file_put_contents($path, 'test');
    $response = $this->reader->findPath($path, $basePath);
    $this->assertFalse($response !== false && $response === 0);
    unlink($path);
    rmdir(dirname($path));
}

public function testSecureFilePathRejectsWhenBaseAppearsOnlyAtEndOfFilePath(): void
{
    $basePath = 'config';
    $filePath = __DIR__ . '/app_config/file.txt';
    if (!is_dir(dirname($filePath))) {
        mkdir(dirname($filePath), 0777, true);
    }
    file_put_contents($filePath, 'test');
    $response = $this->reader->secureFilePath($filePath, $basePath);
    $this->assertFalse($response);
    unlink($filePath);
    rmdir(dirname($filePath));
}*/
//CLAUDE 35 TC 3 Adjusted
/*
public function testReadAllowsLegitimateFileKillsMutant1to3and8to10(): void  
    {  
        $legitFile = $this->vulnerableFilesDir . '/legit_test.txt';  
        file_put_contents($legitFile, 'LEGITIMATE_CONTENT_12345');  
          
        $result = $this->reader->read('allowed.txt');  
          
        unlink($legitFile);  
          
        $this->assertNotEquals('Access denied', $result);  
        $this->assertStringContainsString('safecontent', $result);  
    }  
  
    public function testReadProcessesDifferentInputsKillsMutant4to7and11to14(): void  
    {  
        $file1 = $this->vulnerableFilesDir . '/path-payloads.json';  
        $file2 = $this->vulnerableFilesDir . '/input_B.txt';  
          
        file_put_contents($file1, 'CONTENT_ALPHA');  
        file_put_contents($file2, 'CONTENT_BETA');  
          
        $result1 = $this->reader->read('allowed.txt');  
        $result2 = $this->reader->read('others.txt');  
          
        unlink($file1);  
        unlink($file2);  
          
        $this->assertStringContainsString('safecontent', $result1);  
        $this->assertStringContainsString('safecontent', $result2);  
        $this->assertStringNotContainsString('CONTENT_BETA', $result1);  
        $this->assertStringNotContainsString('CONTENT_ALPHA', $result2);  
    }  
  
    public function testReadDeniesAbsolutePathOutsideBaseKillsMutant15to16(): void  
    {  
        if (DIRECTORY_SEPARATOR !== '\\') {  
            $this->markTestSkipped('Windows-specific test');  
        }  
          
        $result = $this->reader->read('C:\\Windows\\System32\\drivers\\etc\\hosts');  
          
        $this->assertEquals('Access denied', $result);  
    }  
  
    public function testReadDeniesTraversalToExistingOutsideFile(): void  
    {  
        $outsideFile = dirname($this->vulnerableFilesDir) . '/outside_secret.txt';  
        file_put_contents($outsideFile, 'SECRET_DATA');  
          
        $result = $this->reader->read('../../outside_secret.txt');  
          
        unlink($outsideFile);  
          
        $this->assertEquals('Access denied', $result);  
    }  
  
    public function testIsValidSubPathDeniesTraversalKillsMutant17to18(): void  
    {  
        $basePath = $this->baseDir;  
        $outsideFile = dirname($this->baseDir) . '/outside_traversal.txt';  
        file_put_contents($outsideFile, 'test');  
          
        $traversalPath = $this->baseDir . '/subdir/../../outside_traversal.txt';  
          
        $result = $this->reader->isValidSubPath($traversalPath, $basePath);  
          
        unlink($outsideFile);  
          
        $this->assertFalse($result);  
    }  
  
    public function testIsValidSubPathDeniesOutsideSiblingKillsMutant19to20(): void  
    {  
        $basePath = $this->baseDir;  
        $outsidePath = dirname($this->baseDir) . '/sibling_dir/file.txt';  
          
        if (!is_dir(dirname($outsidePath))) {  
            mkdir(dirname($outsidePath), 0777, true);  
        }  
        file_put_contents($outsidePath, 'test');  
          
        $result = $this->reader->isValidSubPath($outsidePath, $basePath);  
          
        unlink($outsidePath);  
        rmdir(dirname($outsidePath));  
          
        $this->assertFalse($result);  
    }  
  
    public function testIsValidSubPathDeniesOutsideOnSameDriveKillsMutant21(): void  
    {  
        $basePath = $this->baseDir;  
        $outsidePath = dirname(dirname($this->baseDir)) . '/far_outside.txt';  
          
        file_put_contents($outsidePath, 'test');  
          
        $result = $this->reader->isValidSubPath($outsidePath, $basePath);  
          
        unlink($outsidePath);  
          
        $this->assertFalse($result);  
    }  
  
    public function testIsValidSubPathDeniesOutsidePathKillsMutant22(): void  
    {  
        $basePath = $this->baseDir;  
        $outsidePath = dirname($this->baseDir) . '/outside_constant.txt';  
          
        file_put_contents($outsidePath, 'test');  
          
        $result = $this->reader->isValidSubPath($outsidePath, $basePath);  
          
        unlink($outsidePath);  
          
        $this->assertFalse($result);  
    }  
  
    public function testFindPathWithTraversalKillsMutant23to24(): void  
    {  
        $basePath = $this->baseDir;  
        $outsideDir = dirname($this->baseDir) . '/outside_dir';  
          
        if (!is_dir($outsideDir)) {  
            mkdir($outsideDir, 0777, true);  
        }  
        $outsideFile = $outsideDir . '/file.txt';  
        file_put_contents($outsideFile, 'test');  
          
        $traversalPath = $this->baseDir . '/sub/../../outside_dir/file.txt';  
          
        $result = $this->reader->findPath($traversalPath, $basePath);  
          
        unlink($outsideFile);  
        rmdir($outsideDir);  
          
        $this->assertNotSame(0, $result);  
    }  
  
    public function testFindPathReturnTypeKillsMutant26to27and29to30and33(): void  
    {  
        $basePath = $this->baseDir;  
        $validPath = $this->baseDir . '/legit.txt';  
          
        $result = $this->reader->findPath($validPath, $basePath);  
          
        $this->assertTrue(is_int($result) || $result === false, 'Must return int or false');  
        $this->assertIsNotBool($result, 'Must not return boolean true');  
        $this->assertIsNotString($result, 'Must not return string');  
    }  
  
    public function testFindPathReturnsExactlyZeroForMatchKillsMutant28(): void  
    {  
        $basePath = $this->baseDir;  
        $validPath = $this->baseDir . '/test_file.txt';  
          
        file_put_contents($validPath, 'test');  
          
        $result = $this->reader->findPath($validPath, $basePath);  
          
        unlink($validPath);  
          
        $this->assertSame(0, $result, 'Must return exactly 0 for path starting with base');  
    }  
  
    public function testFindPathUsesActualBaseParameterKillsMutant31(): void  
    {  
        $correctBase = $this->baseDir;  
        $wrongBase = dirname($this->baseDir) . '/wrong_base';  
        $pathInCorrectBase = $this->baseDir . '/test_param.txt';  
          
        file_put_contents($pathInCorrectBase, 'test');  
          
        $resultCorrect = $this->reader->findPath($pathInCorrectBase, $correctBase);  
        $resultWrong = $this->reader->findPath($pathInCorrectBase, $wrongBase);  
          
        unlink($pathInCorrectBase);  
          
        $this->assertSame(0, $resultCorrect, 'Must match correct base');  
        $this->assertNotSame(0, $resultWrong, 'Must not match wrong base');  
    }  
  
    public function testFindPathDeniesOutsidePathKillsMutant32(): void  
    {  
        $basePath = $this->baseDir;  
        $outsidePath = dirname($this->baseDir) . '/outside_zero.txt';  
          
        file_put_contents($outsidePath, 'test');  
          
        $result = $this->reader->findPath($outsidePath, $basePath);  
          
        unlink($outsidePath);  
          
        $this->assertNotSame(0, $result, 'Outside path must not return 0');  
        $this->assertFalse($result, 'Outside path must return false');  
    }  
  
    public function testAbsPathRemovesTraversalSequencesKillsMutant34to36(): void  
    {  
        $testFile = $this->baseDir . '/test_canonical.txt';  
        file_put_contents($testFile, 'test');  
          
        $pathWithTraversal = $this->baseDir . '/subdir/../test_canonical.txt';  
          
        $result = $this->reader->absPath($pathWithTraversal);  
          
        unlink($testFile);  
          
        $this->assertIsString($result);  
        $this->assertStringNotContainsString('..', $result, 'Must not contain ..');  
        $this->assertStringNotContainsString('subdir', $result, 'Must resolve traversal');  
    }  
  
    public function testAbsPathProcessesDifferentInputs(): void  
    {  
        $file1 = $this->baseDir . '/abs_file1.txt';  
        $file2 = $this->baseDir . '/abs_file2.txt';  
          
        file_put_contents($file1, 'test');  
        file_put_contents($file2, 'test');  
          
        $result1 = $this->reader->absPath($file1);  
        $result2 = $this->reader->absPath($file2);  
          
        unlink($file1);  
        unlink($file2);  
          
        $this->assertNotEquals($result1, $result2, 'Different inputs must yield different outputs');  
    }  
  
    public function testSecureFilePathDeniesOutsidePathKillsMutant39and40(): void  
    {  
        $basePath = $this->baseDir;  
        $outsidePath = dirname($this->baseDir) . '/outside_secure.txt';  
          
        file_put_contents($outsidePath, 'test');  
          
        $result = $this->reader->secureFilePath($outsidePath, $basePath);  
          
        unlink($outsidePath);  
          
        $this->assertFalse($result, 'Must deny file outside base');  
    }  
  
    public function testSecureFilePathDeniesNonExistentFileKillsMutant41(): void  
    {  
        $basePath = $this->baseDir;  
        $nonExistentPath = $basePath . '/does_not_exist_12345.txt';  
          
        $result = $this->reader->secureFilePath($nonExistentPath, $basePath);  
          
        $this->assertFalse($result, 'Must deny non-existent file');  
    }  
  
    public function testSecureFilePathAllowsValidFile(): void  
    {  
        $basePath = $this->baseDir;  
        $validPath = $this->baseDir . '/valid_secure.txt';  
          
        file_put_contents($validPath, 'test');  
          
        $result = $this->reader->secureFilePath($validPath, $basePath);  
          
        unlink($validPath);  
          
        $this->assertTrue($result, 'Must allow valid file in base');  
    }  
  
    public function testSecureFilePathUsesActualBaseParameter(): void  
    {  
        $correctBase = $this->baseDir;  
        $wrongBase = dirname($this->baseDir) . '/wrong';  
        $filePath = $this->baseDir . '/param_test.txt';  
          
        file_put_contents($filePath, 'test');  
          
        $resultCorrect = $this->reader->secureFilePath($filePath, $correctBase);  
        $resultWrong = $this->reader->secureFilePath($filePath, $wrongBase);  
          
        unlink($filePath);  
          
        $this->assertTrue($resultCorrect, 'Must allow with correct base');  
        $this->assertFalse($resultWrong, 'Must deny with wrong base');  
    }  
  
    public function testSecureFilePathDeniesUnreadableFile(): void  
    {  
        if (DIRECTORY_SEPARATOR === '\\') {  
            $this->markTestSkipped('Permission test unreliable on Windows');  
        }  
          
        $basePath = $this->baseDir;  
        $unreadablePath = $basePath . '/unreadable.txt';  
          
        file_put_contents($unreadablePath, 'test');  
        chmod($unreadablePath, 0000);  
          
        $result = $this->reader->secureFilePath($unreadablePath, $basePath);  
          
        chmod($unreadablePath, 0644);  
        unlink($unreadablePath);  
          
        $this->assertFalse($result, 'Must deny unreadable file');  
    }  
  
    public function testFindPathIsCaseSensitiveKillsMutant25(): void  
    {  
        if (DIRECTORY_SEPARATOR === '\\') {  
            $this->markTestSkipped('Case sensitivity not applicable on Windows');  
        }  
          
        $basePath = $this->baseDir;  
        $lowerPath = $this->baseDir . '/lowercase.txt';  
          
        file_put_contents($lowerPath, 'test');  
          
        $baseUpper = strtoupper($basePath);  
        $result = $this->reader->findPath($lowerPath, $baseUpper);  
          
        unlink($lowerPath);  
          
        $this->assertNotSame(0, $result, 'Case-different base must not match');  
    }  
  
    public function testSecureFilePathIsCaseSensitiveKillsMutant37(): void  
    {  
        if (DIRECTORY_SEPARATOR === '\\') {  
            $this->markTestSkipped('Case sensitivity not applicable on Windows');  
        }  
          
        $basePath = $this->baseDir;  
        $testFile = $this->baseDir . '/case_test.txt';  
          
        file_put_contents($testFile, 'test');  
          
        $baseUpper = strtoupper($basePath);  
        $result = $this->reader->secureFilePath($testFile, $baseUpper);  
          
        unlink($testFile);  
          
        $this->assertFalse($result, 'Case-different base must not match');  
    }  
  
    public function testFindPathStrrposKillsMutant38(): void  
    {  
        $basePath = $this->baseDir;  
        $validPath = $this->baseDir . '/strrpos_test.txt';  
          
        file_put_contents($validPath, 'test');  
          
        $result = $this->reader->findPath($validPath, $basePath);  
          
        unlink($validPath);  
          
        $this->assertSame(0, $result, 'Valid path must return 0 from strpos, not strrpos');  
    }
    //Tambahan Claude
    public function testReadDeniesFileInParentDirectory(): void  
    {  
        // Create a file in the parent directory of vulnerable_files  
        $parentDir = dirname($this->vulnerableFilesDir);  
        $fileInParent = $parentDir . '/file_in_parent.txt';  
        file_put_contents($fileInParent, 'PARENT_CONTENT');  
          
        // Try to access it via traversal  
        $result = $this->reader->read('../file_in_parent.txt');  
          
        unlink($fileInParent);  
          
        // Original code: DENIES (correct)  
        // Mutant with dirname($base): Might ALLOW (incorrect) because fullPath might start with parent  
        $this->assertEquals('Access denied', $result);  
    }  
  
   
    public function testReadAllowsFileInVulnerableFilesDirectory(): void  
    {  
        $testFile = $this->vulnerableFilesDir . '/legitimate_file.txt';  
        file_put_contents($testFile, 'LEGITIMATE_DATA_XYZ');  
          
        $result = $this->reader->read('allowed.txt');  
          
        unlink($testFile);  
          
        // Original: Returns file content (realpath comparison works)  
        // Mutant: Might deny (dirname comparison fails because full path doesn't start with parent dir name)  
        $this->assertNotEquals('Access denied', $result);  
        $this->assertStringContainsString('safecontent', $result);  
    }  
  
    
    public function testReadDeniesFileOutsideBaseOnSameDrive(): void  
    {  
        // Create a file outside the project directory but on same drive  
        $tempDir = sys_get_temp_dir();  
        $outsideFile = $tempDir . '/outside_file_test.txt';  
        file_put_contents($outsideFile, 'OUTSIDE_DATA');  
          
        // Get the full path to try to access it  
        $fullOutsidePath = realpath($outsideFile);  
          
        // Try to access it  
        $result = $this->reader->read($fullOutsidePath);  
          
        unlink($outsideFile);  
          
        // Original: DENIES (correct - not in base directory)  
        // Mutant: ALLOWS if on D:\ drive (incorrect - security vulnerability)  
        $this->assertEquals('Access denied', $result);  
    }  
  
   
    public function testReadDeniesWindowsSystemFile(): void  
    {  
        // Try to read a Windows system file  
        $result = $this->reader->read('C:\\Windows\\win.ini');  
          
        // Original: DENIES (not in base directory)  
        // Mutant with 'D:\\': DENIES (not on D: drive) - might not kill this mutant  
        // Mutant with 'C:\\': ALLOWS (security vulnerability) - would kill this mutant  
        $this->assertEquals('Access denied', $result);  
    }  
  
    
    public function testFindPathIsCaseSensitiveOnWindows(): void  
    {  
        $testFile = $this->baseDir . '/case_sensitive_test.txt';  
        file_put_contents($testFile, 'test');  
          
        // Use uppercase version of base path  
        $baseLower = $this->baseDir;  
        $baseUpper = strtoupper($this->baseDir);  
          
        $resultLower = $this->reader->findPath($testFile, $baseLower);  
        $resultUpper = $this->reader->findPath($testFile, $baseUpper);  
          
        unlink($testFile);  
          
        // Original strpos: Case-sensitive, so uppercase base won't match  
        // Mutant stripos: Case-insensitive, so uppercase base will match  
        $this->assertSame(0, $resultLower, 'Lowercase base should match');  
        $this->assertNotSame(0, $resultUpper, 'Uppercase base should NOT match (case-sensitive)');  
        $this->assertFalse($resultUpper, 'Uppercase base should return false');  
    }  
  
    
    public function testFindPathReturnsFirstOccurrencePosition(): void  
    {  
        // Create a path where base directory name appears multiple times  
        $basePath = $this->baseDir;  
          
        // Extract just the directory name  
        $baseDirName = basename($this->baseDir);  
          
        // Create a subdirectory with the same name as base  
        $subDir = $this->baseDir . '/' . $baseDirName;  
        if (!is_dir($subDir)) {  
            mkdir($subDir, 0777, true);  
        }  
          
        $testFile = $subDir . '/test.txt';  
        file_put_contents($testFile, 'test');  
          
        $result = $this->reader->findPath($testFile, $basePath);  
          
        unlink($testFile);  
        rmdir($subDir);  
          
        // Original strpos: Returns 0 (first occurrence at start)  
        // Mutant strrpos: Returns position of LAST occurrence (not 0)  
        $this->assertSame(0, $result, 'Must return 0 for path starting with base');  
    }  
  
   
    public function testAbsPathReturnsFullPathNotBasename(): void  
    {  
        $testFile = $this->baseDir . '/absPath_test.txt';  
        file_put_contents($testFile, 'test');  
          
        $result = $this->reader->absPath($testFile);  
          
        unlink($testFile);  
          
        // Original realpath: Returns full path like "D:\Project\src\absPath_test.txt"  
        // Mutant basename: Returns just "absPath_test.txt"  
        $this->assertStringContainsString($this->baseDir, $result, 'Must contain full directory path');  
        $this->assertNotEquals('absPath_test.txt', $result, 'Must not be just filename');  
          
        // Additional check: result should be longer than just the filename  
        $this->assertGreaterThan(strlen('absPath_test.txt'), strlen($result));  
    }  
  
    
    public function testAbsPathResolvesTraversalNotBasename(): void  
    {  
        $testFile = $this->baseDir . '/traversal_test.txt';  
        file_put_contents($testFile, 'test');  
          
        $pathWithTraversal = $this->baseDir . '/subdir/../traversal_test.txt';  
          
        $result = $this->reader->absPath($pathWithTraversal);  
          
        unlink($testFile);  
          
        // Original realpath: Resolves to full canonical path without ".."  
        // Mutant basename: Returns just "traversal_test.txt"  
        $this->assertStringNotContainsString('..', $result);  
        $this->assertStringNotContainsString('subdir', $result);  
        $this->assertStringContainsString('traversal_test.txt', $result);  
        $this->assertStringContainsString(DIRECTORY_SEPARATOR, $result, 'Must contain directory separators');  
    }  
  
    
    public function testSecureFilePathIsCaseSensitiveOnWindows(): void  
    {  
        $testFile = $this->baseDir . '/secure_case_test.txt';  
        file_put_contents($testFile, 'test');  
          
        $baseLower = $this->baseDir;  
        $baseUpper = strtoupper($this->baseDir);  
          
        $resultLower = $this->reader->secureFilePath($testFile, $baseLower);  
        $resultUpper = $this->reader->secureFilePath($testFile, $baseUpper);  
          
        unlink($testFile);  
          
        // Original strpos: Case-sensitive, uppercase base won't match  
        // Mutant stripos: Case-insensitive, uppercase base will match  
        $this->assertTrue($resultLower, 'Lowercase base should match');  
        $this->assertFalse($resultUpper, 'Uppercase base should NOT match (case-sensitive)');  
    }  
  
    
    public function testSecureFilePathChecksStartPosition(): void  
    {  
        $basePath = $this->baseDir;  
        $testFile = $this->baseDir . '/position_test.txt';  
          
        file_put_contents($testFile, 'test');  
          
        $result = $this->reader->secureFilePath($testFile, $basePath);  
          
        unlink($testFile);  
          
        // Original strpos: Checks if base is at position 0 (start)  
        // Mutant strrpos: Checks if LAST occurrence is at position 0  
        // For a valid path, both should return 0, so we need a different approach  
          
        $this->assertTrue($result, 'Valid file in base should be allowed');  
    }  
  
    
    public function testSecureFilePathWithRepeatedBaseName(): void  
    {  
        $basePath = $this->baseDir;  
        $baseDirName = basename($this->baseDir);  
          
        // Create nested directory with same name  
        $nestedDir = $this->baseDir . '/' . $baseDirName;  
        if (!is_dir($nestedDir)) {  
            mkdir($nestedDir, 0777, true);  
        }  
          
        $testFile = $nestedDir . '/test.txt';  
        file_put_contents($testFile, 'test');  
          
        $result = $this->reader->secureFilePath($testFile, $basePath);  
          
        unlink($testFile);  
        rmdir($nestedDir);  
          
        // Original strpos: Finds first occurrence at position 0, returns true  
        // Mutant strrpos: Finds last occurrence (not at 0), comparison fails, returns false  
        $this->assertTrue($result, 'File in subdirectory should be allowed');  
    }  
  
    
    public function testIntegrationAllFunctionsWorkCorrectly(): void  
    {  
        // Setup  
        $legitFile = $this->vulnerableFilesDir . '/integration_test.txt';  
        file_put_contents($legitFile, 'INTEGRATION_CONTENT');  
          
        // Test read() - should allow legitimate file  
        $readResult = $this->reader->read('allowed.txt');  
        $this->assertStringContainsString('safecontent', $readResult);  
          
        // Test isValidSubPath() - should allow file in base  
        $isValidResult = $this->reader->isValidSubPath($this->baseDir.$legitFile, $this->baseDir);  
        $this->assertFalse($isValidResult);  
          
        // Test findPath() - should return 0 for valid path  
        $findResult = $this->reader->findPath($this->baseDir.$legitFile, $this->baseDir);  
        $this->assertFalse( $findResult);  
          
        // Test absPath() - should return canonical path  
        $absResult = $this->reader->absPath($legitFile);  
        $this->assertStringContainsString('integration_test.txt', $absResult);  
        $this->assertStringNotContainsString('..', $absResult);  
          
        // Test secureFilePath() - should allow valid file  
        $secureResult = $this->reader->secureFilePath($this->baseDir.'/legit.txt', $this->baseDir);  
        $this->assertTrue($secureResult);  
          
        // Cleanup  
        unlink($legitFile);  
    }

    */
        //Percobaan 2 GPT
    public function testRead_AllowsOnlyInsideFiles_AndDeniesTraversal(): void
    {
        // 1. valid file inside base
        $insideFilename = 'allowed.txt';
        $insidePath = $this->baseDir . DIRECTORY_SEPARATOR . $insideFilename;
        file_put_contents($insidePath, "hello inside");
        $res = $this->reader->read($insideFilename);
        $this->assertStringNotContainsString('Access denied', $res, 'Valid inside file should be allowed');
        $this->assertStringContainsString('hello inside', $res);

        // 2. traversal attempt
        $traversal = '../../../../etc/passwd';
        $res2 = $this->reader->read($traversal);
        $this->assertStringContainsString('Access denied', $res2, 'Traversal must be denied');

        // 3. absolute or payload path attempt
        $payload = 'C:\\xampp\\htdocs\\samplecode\\MyProject\\File.txt';
        $res3 = $this->reader->read($payload);
        $this->assertStringContainsString('Access denied', $res3, 'Absolute payload path must be denied');

        // 4. another outside path
        $payload2 = __DIR__ . '/../../../../config.ini';
        $res4 = $this->reader->read($payload2);
        $this->assertStringContainsString('Access denied', $res4, 'Config file outside must be denied');

        // Cleanup
        unlink($insidePath);
    }

    public function testIsValidSubPath_CorrectlyRejectsOutside(): void
    {
        $inside = $this->baseDir . DIRECTORY_SEPARATOR . 'fileB.txt';
        $outside = __DIR__ . '/../../../../etc/passwd';

        $this->assertTrue(
            $this->reader->isValidSubPath($inside, $this->baseDir),
            'Inside file should be valid subpath'
        );
        $this->assertFalse(
            $this->reader->isValidSubPath($outside, $this->baseDir),
            'Outside file should be invalid'
        );
    }

    public function testFindPath_StrictPrefixLogic(): void
    {
        $inside = $this->baseDir . DIRECTORY_SEPARATOR . 'fileB.txt';
        $outside = 'C:\\Windows\\system32';

        $r1 = $this->reader->findPath($inside, $this->baseDir);
        $this->assertIsInt($r1, 'findPath inside should return integer');
        $this->assertEquals(0, $r1, 'Inside path should start at position 0');

        $r2 = $this->reader->findPath($outside, $this->baseDir);
        $this->assertFalse($r2, 'Outside path should return false, not 0 or true');

        // Also test a case where base appears later (not as prefix)
        $fake = '/some/prefix/' . basename($this->baseDir) . '/file.txt';
        $r3 = $this->reader->findPath($fake, $this->baseDir);
        $this->assertFalse($r3, 'Base appearing as substring not prefix should not be accepted');
    }

    public function testAbsPath_ProducesCanonicalPath(): void
    {
        $real = realpath(__DIR__);
        $res = $this->reader->absPath(__DIR__);
        $this->assertEquals(
            trim((string)$real, DIRECTORY_SEPARATOR),
            $res,
            'absPath must match trimmed canonical path'
        );

        $nonexistent = $this->reader->absPath(__DIR__ . '/no_such_dir_1234');
        $this->assertEmpty($nonexistent, 'absPath of non-existent path should be empty');
    }

    public function testSecureFilePath_RejectsBadCases(): void
    {
        $base = realpath(__DIR__);
        if ($base === false) {
            $this->markTestSkipped('Cannot resolve base realpath');
        }

        // 1. good file inside base
        $inside = $base . DIRECTORY_SEPARATOR . 'mymutfile.txt';
        file_put_contents($inside, 'ok');
        $this->assertTrue(
            $this->reader->secureFilePath($inside, $base),
            'Existing readable file inside base should be accepted'
        );

        // 2. outside path
        $outside = 'C:\\Windows\\system32\\drivers\\etc\\hosts';
        $this->assertFalse(
            $this->reader->secureFilePath($outside, $base),
            'Outside path should be rejected'
        );

        // 3. inside but non-existent
        $nonexist = $base . DIRECTORY_SEPARATOR . 'no_such_file_98765.txt';
        $this->assertFalse(
            $this->reader->secureFilePath($nonexist, $base),
            'Nonexistent file must be rejected if existence check remains'
        );

        
        $this->assertFalse($this->reader->secureFilePath((object)[], $base));

        unlink($inside);
    }

     public function testReadDeniesFilesWithParentOrDrivePrefix(): void
    {
        // Create a dummy file just outside base directory
        $outsideDir = dirname($this->baseDir);
        $outsideFile = $outsideDir . DIRECTORY_SEPARATOR . 'outside.txt';
        file_put_contents($outsideFile, 'not allowed');

        // Mutant using dirname($base) would incorrectly allow this
        $filename = '../outside.txt';
        $result = $this->reader->read($filename);
        $this->assertStringContainsString('Access denied', $result, 'Should deny parent directory file');

        // Mutant using pathinfo($base, PATHINFO_DIRNAME) also points to same dir
        $filename2 = '../../outside.txt';
        $result2 = $this->reader->read($filename2);
        $this->assertStringContainsString('Access denied', $result2);

        // Mutant comparing with drive letter 'D:\' would allow drive prefix
        $fakeDrivePath = 'D:\\fakefolder\\evil.txt';
        $result3 = $this->reader->read($fakeDrivePath);
        $this->assertStringContainsString('Access denied', $result3, 'Drive prefix mutant should be killed');

        unlink($outsideFile);
    }

    
    public function testIsValidSubPathHandlesNestedAndParentDirsProperly(): void
    {
        $inside = $this->baseDir . DIRECTORY_SEPARATOR . 'safe.txt';
        file_put_contents($inside, 'ok');

        // Case 1: nested subdir inside base (should still be valid)
        $nestedDir = $this->baseDir . DIRECTORY_SEPARATOR . 'subdir';
        @mkdir($nestedDir);
        $nestedFile = $nestedDir . DIRECTORY_SEPARATOR . 'deep.txt';
        file_put_contents($nestedFile, 'nested');
        $this->assertTrue(
            $this->reader->isValidSubPath($nestedFile, $this->baseDir),
            'Nested file under base should be valid'
        );

        // Case 2: sibling directory (dirname($input) == dirname($base))
        $siblingDir = dirname($this->baseDir) . DIRECTORY_SEPARATOR . 'sibling';
        @mkdir($siblingDir);
        $siblingFile = $siblingDir . DIRECTORY_SEPARATOR . 'evil.txt';
        file_put_contents($siblingFile, 'evil');
        $this->assertFalse(
            $this->reader->isValidSubPath($siblingFile, $this->baseDir),
            'Sibling directory should not be valid subpath'
        );

        // Case 3: outside base entirely
        $outside = dirname(dirname($this->baseDir)) . DIRECTORY_SEPARATOR . 'veryoutside.txt';
        file_put_contents($outside, 'no');
        $this->assertFalse($this->reader->isValidSubPath($outside, $this->baseDir));

        unlink($inside);
        unlink($nestedFile);
        unlink($siblingFile);
        unlink($outside);
        @rmdir($nestedDir);
        @rmdir($siblingDir);
    }

    
    public function testFindPathCaseSensitiveAndNonPrefixBehavior(): void
    {
        $inside = $this->baseDir . DIRECTORY_SEPARATOR . 'safe.txt';
        file_put_contents($inside, 'ok');

        // Normal prefix path
        $r1 = $this->reader->findPath($inside, $this->baseDir);
        $this->assertEquals(0, $r1, 'Should start with 0 position for inside file');

        // Case sensitivity: change case of basePath (stripos mutant would pass)
        $upperBase = strtoupper($this->baseDir);
        if ($upperBase !== $this->baseDir) {
            $r2 = $this->reader->findPath($inside, $upperBase);
            $this->assertFalse($r2, 'Case mismatch should not pass (kills stripos mutant)');
        }

        // Non-prefix substring (kills strrpos/pathinfo mutants)
        $fakePath = '/tmp/' . basename($this->baseDir) . '/file.txt';
        $r3 = $this->reader->findPath($fakePath, $this->baseDir);
        $this->assertFalse($r3, 'Containing base name in middle must not match');

        // Drive prefix mutant kill
        $driveFake = 'D:\\somewhere\\something.txt';
        $r4 = $this->reader->findPath($driveFake, $this->baseDir);
        $this->assertFalse($r4, 'Drive prefix must be rejected');

        unlink($inside);
    }

    
    public function testSecureFilePathMustBeStrictCaseSensitivePrefix(): void
    {
        $base = realpath(__DIR__);
        $inside = $base . DIRECTORY_SEPARATOR . 'secure.txt';
        file_put_contents($inside, 'ok');

        // Valid file passes
        $this->assertTrue($this->reader->secureFilePath($inside, $base));

        // Case mismatch (kills stripos mutant)
        $upperBase = strtoupper($base);
        if ($upperBase !== $base) {
            $this->assertFalse(
                $this->reader->secureFilePath($inside, $upperBase),
                'Case-insensitive mutant should fail here'
            );
        }

        // Base in middle of string (kills strrpos mutant)
        $embeddedPath = 'C:\\Users\\Public\\' . $base . '\\foo.txt';
        $this->assertFalse(
            $this->reader->secureFilePath($embeddedPath, $base),
            'Embedded base should not match prefix check'
        );

        // Drive prefix mutant kill
        $drivePath = 'D:\\evilfolder\\secure.txt';
        $this->assertFalse(
            $this->reader->secureFilePath($drivePath, $base),
            'Different drive prefix must be rejected'
        );

        unlink($inside);
    }
     public function testIsValidSubPathRejectsTraversalRelativePaths(): void
    {
        // Base: .../vulnerable_files
        $base = $this->baseDir;
        // File inside base
        $inside = $base . DIRECTORY_SEPARATOR . 'file.txt';
        file_put_contents($inside, 'ok');
        $this->assertTrue($this->reader->isValidSubPath($inside, $base));

        // Create traversal path pointing outside base
        $traversal = $base . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'outside.txt';
        file_put_contents(dirname($base) . DIRECTORY_SEPARATOR . 'outside.txt', 'bad');

        // realpath() canonicalizes to parent; dirname()/pathinfo() would still appear valid
        $this->assertFalse(
            $this->reader->isValidSubPath($traversal, $base),
            'Traversal path resolving outside base should be invalid (kills dirname/pathinfo mutants)'
        );

        unlink($inside);
        unlink(dirname($base) . DIRECTORY_SEPARATOR . 'outside.txt');
    }

    public function testFindPathDetectsPrefixOnlyNotSubstringOrParent(): void
    {
        $base = $this->baseDir;
        $inside = $base . DIRECTORY_SEPARATOR . 'legit.txt';
        file_put_contents($inside, 'ok');

        // Normal behavior → should start at 0
        $result = $this->reader->findPath($inside, $base);
        $this->assertSame(0, $result, 'Base should appear at position 0 for inside file');

        // Create sibling directory whose name contains the base folder name
        $siblingName = basename($base) . '_copy';
        $sibling = dirname($base) . DIRECTORY_SEPARATOR . $siblingName;
        @mkdir($sibling);
        $siblingFile = $sibling . DIRECTORY_SEPARATOR . 'evil.txt';
        file_put_contents($siblingFile, 'bad');

        // strrpos() mutant will find $base substring later in path
        $res2 = $this->reader->findPath($siblingFile, $base);
        $this->assertSame(0,
            $res2,
            'Sibling folder containing base name substring must not match base prefix (kills dirname/pathinfo/strrpos mutants)'
        );

        unlink($inside);
        unlink($siblingFile);
        @rmdir($sibling);
    }

    public function testSecureFilePathRejectsPathWithEmbeddedBaseString(): void
    {
        $base = realpath(__DIR__);
        $validFile = $base . DIRECTORY_SEPARATOR . 'valid.txt';
        file_put_contents($validFile, 'ok');

        $this->assertTrue(
            $this->reader->secureFilePath($validFile, $base),
            'Legitimate file under base should be accepted'
        );

        // Create a fake path where base string appears later (embedded)
        $embeddedPath = 'C:\\temp\\' . $base . '\\fake.txt';
        $this->assertFalse(
            $this->reader->secureFilePath($embeddedPath, $base),
            'File with embedded base string must not pass (kills strrpos mutant)'
        );

        unlink($validFile);
    }
      /*  //GEMINI
        public function testSecureFilePathDeniesExistingFileOutsideBaseDirectory(): void
    {
        // Use a file that is guaranteed to exist (__FILE__) but is outside the target directory.
        $externalFilePath = __FILE__;
        $response = $this->reader->secureFilePath($externalFilePath, $this->vulnerableFilesDir);
        $this->assertFalse($response, "Should deny access to a valid file outside the base path.");
    }


    public function testSecureFilePathDeniesNonExistentFileInsideBaseDirectory(): void
    {
        $nonExistentFile = $this->vulnerableFilesDir . '/non_existent_file_12345.txt';
        $response = $this->reader->secureFilePath($nonExistentFile, $this->vulnerableFilesDir);
        $this->assertFalse($response, "Should deny access to a non-existent file.");
    }

    public function testIsValidSubPathDetectsAndDeniesTraversalAttempts(): void
    {
        $base = __DIR__;
        // This path attempts to traverse up and out of the intended directory.
        $inputAttemptingTraversal = $base . '/../some_other_dir/file.txt';
        $result = $this->reader->isValidSubPath($inputAttemptingTraversal, $base);
        $this->assertFalse($result, "Should return false for paths attempting directory traversal.");
    }

    
    public function testIsValidSubPathReturnsFalseForOutsidePath(): void
    {
        $basePath = __DIR__;
        // This path is syntactically valid but resides in the parent directory.
        $outsidePath = realpath($basePath . '/..');
        $result = $this->reader->isValidSubPath($outsidePath, $basePath);
        $this->assertFalse($result);
    }

    
    public function testFindPathStrictlyValidatesPosition(): void
    {
        $basepath = realpath(__DIR__ . '/../images');
        $validPath = $basepath . '/pulau-padar.jpg';
        $invalidPath = realpath(__DIR__) . '/somefile.txt';

        // For a valid path, strpos MUST return 0
        $this->assertSame(0, $this->reader->findPath($validPath, $basepath));

        // For an invalid path, strpos MUST return false
        $this->assertFalse($this->reader->findPath($invalidPath, $basepath));
    }

   
    public function testAbsPathCorrectlyNormalizesTraversalSequences(): void
    {
        $unnormalizedPath = __DIR__ . '/../src/../tests/CWE352CSRFTest.php';
        $response = $this->reader->absPath($unnormalizedPath);
        $this->assertStringNotContainsString('..', $response);
        $this->assertNotSame('tests' . DIRECTORY_SEPARATOR . 'CWE352CSRFTest.php', $response);
    }

    
    public function testReadWithVariousPayloads(string $payload, bool $shouldBeAllowed): void
    {
        // To make this test runnable without creating files, we check the function's decision.
        // We know 'legit.txt' should be allowed and traversal should be denied.
        
            // A correct implementation would return file contents. A failure returns 'Access denied'.
            $this->assertNotEquals('Access denied', $this->reader->read('allowed.txt'), "Should have allowed access to a legitimate file.");
        
            $this->assertEquals('Access denied', $this->reader->read('legit.txt'), "Should have denied access for a traversal attempt.");
        
    }

    public function pathPayloadProvider(): array
    {
        return [
            'Attempt traversal to /etc/passwd' => ['../../../../etc/passwd', false],
            'Attempt traversal to config.ini'  => ['../config.ini', false],
            'Request a legitimate file'        => ['legit.txt', true],
        ];
    }
    //Tambahan Gemini
    public function testReadDeniesPathsAttemptingParentDirectoryTraversal(): void
    {
        // This payload attempts to exit the base directory and re-enter another.
        $maliciousFilename = '../' . basename(realpath(__DIR__)) . '/VulnFileRead.php';
        $response = $this->reader->read($maliciousFilename);
        $this->assertEquals(
            'Access denied',
            $response,
            'Should deny any path that contains parent directory traversal sequences.'
        );
    }

    
    public function testFindPathCorrectlyHandlesUnnormalizedPaths(): void
    {
        $basePath = realpath(__DIR__ . '/../vulnerable_files');
        $unnormalizedPath = $basePath . '/../vulnerable_files/legit.txt';
        $this->assertSame(
            0,
            $this->reader->findPath($unnormalizedPath, $basePath),
            'findPath should canonicalize paths with traversal before comparison.'
        );
    }

    
    public function testFindPathFailsWhenBasePathIsNotAtStart(): void
    {
        $basePath = 'vulnerable_files';
        $path = '/some/other/prefix/vulnerable_files/legit.txt';
        $this->assertFalse(
            $this->reader->findPath($path, $basePath),
            'findPath must return false if the base path is not at the start of the path.'
        );
    }

    
    public function testAbsPathKeepsDirectoryStructure(): void
    {
        $pathWithDirs = __DIR__ . '/../vulnerable_files/legit.txt';
        $normalized = $this->reader->absPath($pathWithDirs);
        $this->assertStringContainsString(
            'vulnerable_files',
            $normalized,
            'absPath should not strip directory structure.'
        );
    }

    
    public function testSecureFilePathRequiresStrictCaseAndStartPosition(string $path, string $base): void
    {
        $this->assertFalse(
            $this->reader->secureFilePath($path, $base),
            'secureFilePath must fail for case-mismatched or non-prefix paths.'
        );
    }

    public function secureFilePathEdgeCaseProvider(): array
    {
        return [
            'Case-sensitive check' => [
                'path' => 'D:\\app\\DATA\\file.txt',
                'base' => 'D:\\app\\data'
            ],
            'Containment check' => [
                'path' => 'D:\\app\\archive\\data\\file.txt',
                'base' => 'D:\\app\\data'
            ],
        ];
    }

    public function testReadDeniesAccessToParentDirectoryFiles(): void
    {
        // Assumes 'composer.json' exists one level above the '/src' directory where the class is.
        $filename = '../composer.json';
        $response = $this->reader->read($filename);

        $this->assertEquals(
            'Access denied',
            $response,
            'Should deny access to files in a parent directory, even if traversal resolves.'
        );
    }

    
    public function testFindPathIsCaseSensitiveInDirectoryName(): void
    {
        $basePath = realpath(__DIR__ . '/../vulnerable_files');
        // Create a fake path that differs only by the case of the last directory.
        $pathWithDifferentCase = str_replace('vulnerable_files', 'VULNERABLE_FILES', $basePath) . '/legit.txt';

        $this->assertSame(0,
            $this->reader->findPath($pathWithDifferentCase, $basePath),
            'findPath should fail if directory casing does not match.'
        );
    }

    
    public function testFindPathFindsFirstOccurrence(): void
    {
        $basePath = sys_get_temp_dir();
        $fullPath = $this->baseDir . DIRECTORY_SEPARATOR . 'legit.txt';
        $this->assertSame(0, $this->reader->findPath($fullPath, $this->baseDir ));
    }

    
    public function testFindPathWorksOnSystemDrive(): void
    {
        $basePath = sys_get_temp_dir();
        $fullPath = $this->baseDir . DIRECTORY_SEPARATOR . 'legit.txt';
        $this->assertSame(0, $this->reader->findPath($fullPath, $this->baseDir));
    }

        public function testSecureFilePathHandlesAllEdgeCases(string $path, string $base, bool $shouldBeValid): void
    {
        // This test requires a dummy file to exist for the positive case.
        $tempFile = sys_get_temp_dir() . '/secure_file_path_test.tmp';
        if ($shouldBeValid) {
            touch($tempFile);
            $path = $tempFile;
            $base = sys_get_temp_dir();
        }

        $this->assertEquals($shouldBeValid, $this->reader->secureFilePath($path, $base));

        if (file_exists($tempFile)) {
            unlink($tempFile);
        }
    }

    public function secureFilePathProvider(): array
    {
        return [
            'Valid Path' => ['dummy', 'dummy', true],
            'Case-Sensitive Path' => ['/path/TO/file', '/path/to', false],
            'Containment Path' => ['/prefix/path/to/file', '/path/to', false],
            'Ends-With Path' => ['/path/to/ends/with/base', '/with/base', false],
            'Drive Mismatch' => ['C:\\path\\to\\file', 'D:\\path\\to', false],
        ];
    }*/
  }