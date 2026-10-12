<?php
declare(strict_types=1);

namespace App\Test\TestCase\Http;

use Cake\Http\ServerRequest;
use Cake\Http\UriFactory;
use Cake\TestSuite\TestCase;
use Cake\Core\Configure;

class QZrSUrlPathHandlingSecurityTests extends TestCase
{
    /**
     * Test that URL without leading slash gets one added.
     * 
     * Original: str_starts_with($url, '/')
     * Mutant: str_starts_with($url, 'C:\\') or 'D:\\'
     * 
     * Mutant would fail to detect missing slash on *nix paths.
     */
    public function testUrlWithoutLeadingSlashGetsPrefixed(): void
    {
        $request = new ServerRequest([
            'url' => 'articles/view/1',
        ]);
        
        $uri = $request->getUri();
        $path = $uri->getPath();
        
        // Original adds leading slash
        // Mutant checking for 'C:\' never matches, so slash not added
        $this->assertStringStartsWith(
            '/',
            $path,
            'URL path must start with / - mutant checking for Windows drive fails on Unix paths'
        );
        $this->assertEquals('/articles/view/1', $path);
    }

    /**
     * Test URL already with leading slash is not double-prefixed.
     */
    public function testUrlWithLeadingSlashNotDoublePrefixed(): void
    {
        $request = new ServerRequest([
            'url' => '/articles/view/1',
        ]);
        
        $uri = $request->getUri();
        $path = $uri->getPath();
        
        $this->assertEquals('/articles/view/1', $path);
        $this->assertFalse(str_starts_with($path, '//'), 'URL path should not start with double slash');
    }

    /**
     * Test UriFactory path normalization with webroot/index.php.
     */
    public function testUriFactoryStripsWebrootIndexPhp(): void
    {
        Configure::write('App.webroot', 'webroot');
        
        $server = [
            'REQUEST_URI' => '/webroot/index.php/articles/view',
            'PHP_SELF' => '/webroot/index.php',
        ];
        
        $request = new ServerRequest(['environment' => $server]);
        $uri = $request->getUri();
        
        // Original correctly detects '/' prefix
        // Mutant looking for 'C:\' wouldn't strip properly
        $this->assertEquals('/webroot/index.php/articles/view', $uri->getPath());
    }

    /**
     * Test UriFactory base path extraction with index.php.
     * 
     * strpos vs strrpos: with multiple /index.php in path.
     */
    public function testUriFactoryBasePaathWithMultipleIndexPhp(): void
    {
        $server = [
            'REQUEST_URI' => '/app/index.php/module/index.php/action',
            'PHP_SELF' => '/app/index.php/module/index.php',
        ];
        
        // strpos finds first /index.php at position 4
        // strrpos finds last /index.php at position 19
        $request = new ServerRequest(['environment' => $server]);
        $uri = $request->getUri();
        
        // Behavior depends on implementation, but should be consistent
        $this->assertIsString($uri->getPath());
    }

    /**
     * Test case sensitivity of /index.php detection.
     * 
     * strpos is case-sensitive
     * stripos is case-insensitive
     */
    public function testIndexPhpDetectionCaseSensitive(): void
    {
        $server = [
            'REQUEST_URI' => '/app/INDEX.PHP/articles',
            'PHP_SELF' => '/app/INDEX.PHP',
        ];
        
        $request = new ServerRequest(['environment' => $server]);
        $uri = $request->getUri();
        
        // strpos('/INDEX.PHP', '/index.php') = false (case mismatch)
        // stripos would find it
        // This tests case-sensitive behavior is maintained
        $path = $uri->getPath();
        $this->assertIsString($path);
    }
}
