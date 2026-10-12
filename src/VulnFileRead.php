<?php
namespace App;
//const basepath = __DIR__;
class VulnFileRead
{
public function read($filename): string
    {
        // Deliberate lack of sanitization for path traversal simulation
        $base = __DIR__ . '/../vulnerable_files/';
        $fullPath = realpath($base . $filename);

        // Vulnerable logic — only checks that $fullPath starts with base
        if ($fullPath && str_starts_with($fullPath, realpath($base))) {
            return file_get_contents($fullPath);
        }
        
        
        return 'Access denied';
    }

function isValidSubPath(string $inputPath, string $basePath): bool
{
    $realInput = realpath($inputPath);
    $realBase  = realpath($basePath);
    if ($realInput === false || $realBase === false) {
        return false;
    }
    return str_starts_with($realInput, $realBase);
}
     public function findPath($path,  $basePath)
    {
    //$Spath=$path;
    return strpos(realPath($path), $basePath);
    }
    public function absPath($path)
    {
    $normalizedPath = trim(realpath($path), DIRECTORY_SEPARATOR);
    return $normalizedPath;
    }

    function secureFilePath($filePath, $basePath) {
    if (!is_string($filePath)) {
        return false;
    }
    if (strpos($filePath, $basePath)!== 0) {
        return false; 
    }
     if (file_exists($filePath) 
        && is_readable($filePath)) {
        return true;
    } else {
        return false;
    }

}

}

  


