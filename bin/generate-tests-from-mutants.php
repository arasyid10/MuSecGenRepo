#!/usr/bin/env php
<?php
declare(strict_types=1);

/**
 * Parse Infection JSON → gabungkan ke prompt → panggil OpenAI Chat Completions → tulis test ke tests/Generated/.
 *
 * Env yang dibutuhkan:
 *   OPENAI_API_KEY=sk-xxxx
 *
 * Argumen opsional:
 *   --log=build/infection-log.json
 *   --prompt=prompts/mutant_fix_prompt.md
 *   --model=gpt-4o-mini
 */

const DEFAULT_LOG    = 'build/infection-log.json';
const DEFAULT_PROMPT = 'prompts/mutant_fix_prompt.md';
const DEFAULT_MODEL  = 'gpt-4o'; // gpt-4o, gpt-4o-mini, gpt-3.5-turbo

function arg(string $name, string $default): string {
    foreach ($GLOBALS['argv'] as $v) {
        if (str_starts_with($v, "--$name=")) return substr($v, strlen("--$name="));
    }
    return $default;
}

$logPath    = arg('log', DEFAULT_LOG);
$promptPath = arg('prompt', DEFAULT_PROMPT);
$model      = arg('model', DEFAULT_MODEL);

$apiKey = getenv('OPENAI_API_KEY');
if (!$apiKey) {
    fwrite(STDERR, "Missing OPENAI_API_KEY env.\n");
    exit(2);
}
if (!is_file($logPath))   { fwrite(STDERR, "Infection JSON not found: $logPath\n"); exit(3); }
if (!is_file($promptPath)){ fwrite(STDERR, "Prompt file not found: $promptPath\n"); exit(4); }

$promptBase = file_get_contents($promptPath);

// --- 1) Parse Infection JSON ---
$json = json_decode(file_get_contents($logPath), true);
if (!is_array($json)) { fwrite(STDERR, "Invalid JSON in $logPath\n"); exit(5); }

// Ambil mutants yang Escaped/Survived
$survived = [];
$iter = [];
if (isset($json['mutants']) && is_array($json['mutants'])) {
    $iter = $json['mutants'];
} elseif (isset($json['files']) && is_array($json['files'])) {
    foreach ($json['files'] as $fileEntry) {
        foreach (($fileEntry['mutants'] ?? []) as $m) { $iter[] = $m; }
    }
} elseif (is_array($json)) {
    $iter = $json;
}
foreach ($iter as $m) {
    $status   = strtolower((string)($m['status'] ?? $m['result'] ?? ''));
    $isEscape = str_contains($status, 'escaped') || str_contains($status, 'survived');
    if (!$isEscape) continue;

    $survived[] = [
        'file'        => $m['file'] ?? $m['filename'] ?? 'unknown',
        'line'        => $m['line'] ?? $m['startLine'] ?? null,
        'mutator'     => $m['mutator'] ?? $m['mutatorName'] ?? 'unknown',
        'original'    => $m['originalCode'] ?? $m['original'] ?? null,
        'mutated'     => $m['mutatedCode']  ?? $m['mutated']  ?? null,
        'diff'        => $m['diff'] ?? null,
        'testOutput'  => $m['processOutput'] ?? $m['testOutput'] ?? null,
    ];
}
if (!$survived) { echo "No survived/escaped mutants found.\n"; exit(0); }

// --- 2) Bangun blok ringkasan survived ---
$survivedBlock = "# Survived Mutants (from infection-log.json)\n\n";
foreach ($survived as $i => $m) {
    $idx = $i + 1;
    $survivedBlock .= "## [$idx] {$m['mutator']} @ {$m['file']}" . ($m['line'] ? ":{$m['line']}" : "") . "\n";
    if ($m['diff']) {
        $survivedBlock .= "```diff\n{$m['diff']}\n```\n";
    } else {
        if ($m['original']) $survivedBlock .= "**Original:**\n```php\n{$m['original']}\n```\n";
        if ($m['mutated'])  $survivedBlock .= "**Mutated:**\n```php\n{$m['mutated']}\n```\n";
    }
    if (!empty($m['testOutput'])) {
        $survivedBlock .= "<details><summary>Test Output</summary>\n\n```\n{$m['testOutput']}\n```\n</details>\n";
    }
    $survivedBlock .= "\n";
}

// --- 3) Final prompt ---
$finalPrompt = $promptBase . "\n\n" . $survivedBlock;

// --- 4) Panggil OpenAI Chat Completions ---
$payload = [
    "model" => $model,
    "messages" => [
        [
            "role" => "system",
            "content" => "You are an expert PHP tester. Generate minimal, precise PHPUnit tests that KILL the listed survived mutants without changing production code. Use accurate assertions and briefly explain above each test."
        ],
        [
            "role" => "user",
            "content" => $finalPrompt
        ]
    ],
    "temperature" => 0.2
];

[$ok, $resp] = call_openai_chat($payload, $apiKey);
if (!$ok) { fwrite(STDERR, "OpenAI error: $resp\n"); exit(6); }

$testCode = extract_code_from_markdown($resp);
if (!$testCode) $testCode = $resp;

// --- 5) Tulis hasil ke tests/Generated/ ---
$outDir = __DIR__ . '/../tests/Generated';
if (!is_dir($outDir)) @mkdir($outDir, 0777, true);
$outFile = $outDir . '/GeneratedMutantKillerTest.php';
file_put_contents($outFile, $testCode);
echo "Wrote: $outFile\n";

// --- 6) (Opsional) lint & jalankan PHPUnit ---
passthru(PHP_BINARY . ' -l ' . escapeshellarg($outFile));
passthru('vendor/bin/phpunit --filter GeneratedMutantKillerTest');

exit(0);

// ===== Helpers =====
function call_openai_chat(array $payload, string $apiKey): array {
    $ch = curl_init('https://api.openai.com/v1/chat/completions'); // Chat Completions API
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $apiKey, // Auth header
        ],
        CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE),
    ]);
    $res  = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    if ($res === false) { $err = curl_error($ch); curl_close($ch); return [false, $err]; }
    curl_close($ch);

    $data = json_decode($res, true);
    if ($code < 200 || $code >= 300) return [false, $res];

    $text = $data['choices'][0]['message']['content'] ?? '';
    return [true, $text];
}

function extract_code_from_markdown(string $md): string {
    if (preg_match_all('/```php\\s*(.*?)```/si', $md, $m) && !empty($m[1])) {
        return "<?php\n\n" . implode("\n\n", $m[1]) . "\n";
    }
    return '';
}
