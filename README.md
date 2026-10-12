# 🛡️ Path Traversal & Authorization Bypass Vulnerability Simulation

This dummy PHP project is designed to **simulate and test real-world file access vulnerabilities**, specifically:

- 🔓 **Directory & Path Traversal (CWE-22 to CWE-36)**
- 🧑‍💻 **Authorization Bypass via Predictable IDs (CWE-639)**
- ✅ PHPUnit tests all pass (expected behavior)
- 🧪 Infection detects **surviving mutants** due to intentionally weak validation logic

The project is useful for:

- Security researchers
- QA testers
- Students studying web security
- Test case mutation testers

---

## 🧱 Project Structure
```
traversal-vulnerabilities/
├── src/
│ ├── VulnFileRead.php # Path traversal simulation
│ └── UserProfileRead.php # Auth bypass simulation
├── tests/ # PHPUnit test cases (CWE-specific)
│ └── CweXX<...>Test.php # Individual CWE test cases
├── vulnerable_files/ # Target files for test access
│ ├── etc/ # Simulated /etc/passwd
│ ├── secret_dir/ # Simulated sensitive content
│ ├── safe_dir/ # Legitimate user-accessible files
│ └── users/ # Simulated user profile directories
├── patterns.json # Attack patterns used in tests
├── phpunit.xml.dist # PHPUnit configuration
├── infection.json.dist # Infection mutation config
└── composer.json # Autoload & dependencies
```


---

## 🔍 Vulnerability Simulation Explanation

### `src/VulnFileRead.php`

- Core vulnerable logic using `realpath()` and `str_starts_with()`
- Doesn't sanitize or normalize input paths
- Allows traversal via obfuscation or encoding
- ❗Allows Infection to mutate path checks without failing tests

### `src/UserProfileRead.php`

- Simulates user profile file access by `user_id`
- No ownership validation — predictable ID = access to any user
- Covers **CWE-639** (Authorization Bypass)

---

## 🧪 Test Cases Breakdown (by CWE)

Each test file maps directly to a **CWE (Common Weakness Enumeration)** ID and simulates attack vectors found in real systems.

| CWE ID | Name                                 | Description |
|--------|--------------------------------------|-------------|
| CWE-23 | Relative Path Traversal              | `../../` or `..\\..\\` to escape base dir |
| CWE-24 | Traversal to Specific Directory      | Accessing `../admin`, `../config` |
| CWE-25 | Absolute Path Access                 | Access `/etc/passwd` or `C:\Windows\...` |
| CWE-26 | Obfuscated Traversal                 | Triple-dot: `.../...//` |
| CWE-27 | Folder Up One Level                  | Legit path with `/..` |
| CWE-28 | Double Encoded Traversal             | `%252e%252e%252f` decoded to `../` |
| CWE-29 | Unicode Traversal                    | Unicode `\u002e` trick |
| CWE-30 | Null Byte Injection                  | `../../etc/passwd%00.png` bypass |
| CWE-31 | Mid-Path Traversal                   | E.g. `images/../../admin/...` |
| CWE-32 | Path Normalization (`dir/..`)        | E.g. `assets/../` |
| CWE-33 | Double Upward Traversal              | `folder/sub/../../` |
| CWE-34 | Multi-Level Traversal                | 3+ level traversal |
| CWE-35 | Extra Dots in Filename               | E.g. `secret.txt...` |
| CWE-36 | Mixed Slashes Traversal              | Combining `/`, `\`, `\\` |
| CWE-639| Authorization Bypass via ID          | Predictable ID = access any user |

---

## ✅ How to Run

### 1. Install Dependencies

```bash
composer install
```

### 2. Run PHPUnit

```bash
vendor/bin/phpunit
```

### 3. Run Infection (Mutation Testing)

```bash
vendor/bin/infection
```

⚠️ Infection will detect surviving mutants due to poor validation logic, simulating real-world exploitation potential.


### ⚙️ Requirements
- PHP >= 8.0
- Composer
- PHPUnit (via composer)
- Infection mutation testing (via composer)
