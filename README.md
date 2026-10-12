# 🛡️ Traversal Vulnerabilities and Mutation Testing Sandbox

This project is a PHP security testbed designed to simulate several realistic weaknesses in web applications, especially around:

- 🔓 Path traversal and directory escape vulnerabilities (CWE-22 to CWE-36)
- 🧑‍💻 Authorization bypass caused by predictable identifiers (CWE-639)
- 🧪 Mutation testing using Infection to evaluate whether protective checks survive typical code mutations
- 🔐 CSRF token validation and anti-CSRF guard logic

The repository is useful for:

- Security research and demonstration
- Classroom training in web application security
- Mutation testing experiments
- Evaluating the effectiveness of sanitization and validation logic
- Testing whether protective checks remain robust under code mutation

---

## 🎯 Project objectives

This project intentionally includes vulnerable patterns and defensive test cases so that researchers can study how weaknesses manifest and how mutation testing exposes fragile code.

It combines three major themes:

1. Path traversal exploitation scenarios
2. Authorization bypass via predictable user identifiers
3. CSRF validation logic and token handling under mutation pressure

---

## 🧱 Project structure

```text
traversal-vulnerabilities-main/
├── src/
│   ├── VulnFileRead.php              # Path traversal simulation
│   ├── UserProfileRead.php           # Authorization bypass scenario
│   ├── dwacsrf.php                  # CSRF-related logic examples
│   ├── dvwaipl.php                  # Security logic / input validation helpers
│   ├── mutillidaeCSRFTokenHandler.php # CSRF token handler mock-up
│   ├── EncodingHandler.php          # Encoding/normalization logic used in traversal tests
│   └── Mutator/                     # Mutation operator implementations
│       ├── Html/
│       ├── Security/
│       └── ...
├── tests/
│   ├── Cwe22PathTraversalTests.php
│   ├── Cwe22IPLChainTests.php
│   ├── Cwe639AuthorizationBypassTest_.php
│   ├── CSRFChainTests.php
│   ├── CSRFFewTests.php
│   ├── CSRFZeroTests.php
│   ├── MutillidaeCSRFTokenHandlerTests.php
│   └── ...
├── config/
│   ├── path-payloads.json
│   ├── html-value-payloads.json
│   └── settings.ini
├── vulnerable_files/
│   └── sample sensitive and safe files used by the tests
├── patterns.json
├── phpunit.xml
├── infection.json5
├── composer.json
├── composer.lock
├── Dockerfile
├── docker-compose.yml
├── README.md
├── reports/
│   └── mutation and coverage reporting artifacts
└── vendor/
```

---

## 🔍 Vulnerability scenarios covered

### 1. Path traversal and file access violations

`src/VulnFileRead.php` demonstrates how unsafe file path handling may allow users to escape a restricted directory using values such as:

- `../`
- `..\\`
- encoded traversal payloads
- null-byte variants
- multi-level traversal paths
- mixed separators and normalization tricks

This covers CWE-22 and related traversal weaknesses such as CWE-23 to CWE-36.

### 2. Authorization bypass via predictable IDs

`src/UserProfileRead.php` simulates access to user-specific resources using predictable identifiers. If the application trusts a user-supplied ID without validating ownership or authorization, an attacker may access records outside their scope.

This aligns with:

- CWE-639: Authorization Bypass Through User-Controlled Key

### 3. Mutation operator testing

The project includes a dedicated mutation area under `src/Mutator/` and related reports under `reports/`. These mutation operators simulate code changes that may break or weaken validation logic, such as:

- replacing string checks with weaker comparisons
- mutating filtering logic
- modifying path payload operators
- altering HTML value handling
- changing security-related comparisons or conditional checks

This is useful for observing whether tests actually catch weak or mutated logic, which is the core purpose of mutation testing with Infection.

### 4. CSRF validation and security checks

This project also includes explicit Cross-Site Request Forgery (CSRF) testing. CSRF is a web vulnerability where an attacker tricks a logged-in user into submitting a malicious request that the application accepts as valid.

The repository contains dedicated CSRF-focused test suites, including:

- `CSRFChainTests.php`
- `CSRFFewTests.php`
- `CSRFZeroTests.php`
- `CSRFChainMCPTests.php`
- `MutillidaeCSRFTokenHandlerTests.php`
- `DvwaCsrfTokenTests.php`
- `src/dwacsrf.php`
- `src/mutillidaeCSRFTokenHandler.php`

These tests evaluate important CSRF protections such as:

- generation of CSRF tokens in HTML forms
- validation of token values before accepting requests
- comparison that is case-sensitive and length-sensitive
- rejection of tampered, invalid, or mismatched tokens
- uniqueness and randomness of generated tokens
- hidden input naming conventions such as `token-csrf`
- secure handling of session-based token verification

This project therefore covers both file traversal weaknesses and CSRF protection logic in a single security testing benchmark.

---

## 🧪 Test categories

The repository includes numerous PHPUnit test groups, including:

| Category | Focus |
|---|---|
| CWE-22 / Path Traversal | Escaping the base directory using encoded or normalized payloads |
| CWE-639 | Accessing unauthorized resources via predictable IDs |
| CSRF | Hidden-token generation, validation, and strict comparison |
| Mutation testing | Checking whether mutants survive or are killed by tests |
| Security chain testing | Combined logic checks for multi-step exploit chains |

---

## ✅ How to run

### Install dependencies

```bash
composer install
```

### Run PHPUnit

```bash
vendor/bin/phpunit
```

### Run mutation testing with Infection

```bash
vendor/bin/infection
```

### Optional: run specific suites

```bash
vendor/bin/phpunit --filter CSRF
vendor/bin/phpunit --filter PathTraversal
vendor/bin/phpunit --filter Authorization
```

---

## ⚙️ Requirements

- PHP >= 8.0
- Composer
- PHPUnit
- Infection mutation testing
- Optional Docker support via `Dockerfile` and `docker-compose.yml`

---

## 📝 Notes

This project is intentionally designed to illustrate security weaknesses in a controlled environment. The vulnerable behavior is not meant to be deployed in production as-is. It is primarily used for learning, experimentation, and security validation through automated tests and mutation analysis.

The combination of traversal bugs, authorization issues, mutation operators, and CSRF validation testing makes it a useful benchmark for understanding how security controls can fail under adversarial input and mutation-based evaluation.
