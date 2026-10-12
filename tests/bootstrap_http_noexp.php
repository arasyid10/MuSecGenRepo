<?php
declare(strict_types=1);

// Pastikan ENV tersedia SEBELUM tests/bootstrap.php dijalankan
$dsn = 'sqlite:///:memory:';
$schema = __DIR__ . '/schema.php';

putenv("DATABASE_TEST_URL={$dsn}");
putenv("DB_URL={$dsn}");
putenv("FIXTURE_SCHEMA_METADATA={$schema}");

$_ENV['DATABASE_TEST_URL'] = $dsn;
$_SERVER['DATABASE_TEST_URL'] = $dsn;

$_ENV['DB_URL'] = $dsn;
$_SERVER['DB_URL'] = $dsn;

$_ENV['FIXTURE_SCHEMA_METADATA'] = $schema;
$_SERVER['FIXTURE_SCHEMA_METADATA'] = $schema;

// Jalankan bootstrap CakePHP yang asli
require __DIR__ . '/bootstrap.php';