<?php
declare(strict_types=1);

namespace Cake\Test\TestCase\Http\Eksperiment;

use Cake\Core\Configure;
use Cake\TestSuite\TestCase;

abstract class EksperimentTestCase extends TestCase
{
    /** @var array<string,mixed> */
    private array $appBackup = [];
    private string $defaultCharsetBackup = 'UTF-8';
    private string $mbEncodingBackup = 'UTF-8';

    protected function setUp(): void
    {
        parent::setUp();

        // Backup state global yang sering "terkontaminasi"
        $this->appBackup = (array)Configure::read('App');

        $this->defaultCharsetBackup = (string)(ini_get('default_charset') ?: 'UTF-8');

        if (function_exists('mb_internal_encoding')) {
            $this->mbEncodingBackup = (string)(mb_internal_encoding() ?: 'UTF-8');
        }
    }

    protected function tearDown(): void
    {
        // Restore Configure::App
        Configure::write('App', $this->appBackup);

        // Hardening: pastikan encoding tidak pernah null
        $encoding = $this->appBackup['encoding'] ?? 'UTF-8';
        if (!$encoding) {
            $encoding = 'UTF-8';
        }
        Configure::write('App.encoding', $encoding);

        // Restore charset/encoding runtime
        @ini_set('default_charset', $this->defaultCharsetBackup);
        if (function_exists('mb_internal_encoding')) {
            @mb_internal_encoding($this->mbEncodingBackup);
        }

        parent::tearDown();
    }
}