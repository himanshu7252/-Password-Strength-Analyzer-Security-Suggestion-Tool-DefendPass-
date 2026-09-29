# Password Strength Analyzer & Security Suggestion Tool (DefendPass)

[![Python 3.11](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Flask 3.1](https://img.shields.io/badge/Flask-3.1%2B-green.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/pytest-33%20passed-brightgreen.svg)](https://pytest.org/)
[![NIST SP 800-63B](https://img.shields.io/badge/Standard-NIST%20SP%20800--63B-purple.svg)](https://pages.nist.gov/800-63-3/sp800-63b.html)
[![Privacy-by-Design](https://img.shields.io/badge/Privacy-100%25%20In--Memory-orange.svg)](#privacy-design)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A privacy-focused, defensive cybersecurity application engineered to evaluate password resilience using length depth, unpredictability, pattern resistance, entropy concepts, and personalized security recommendations.

---

## Overview

Traditional password meters judge password quality on an outdated assumption: verifying whether a credential contains uppercase, lowercase, numbers, and symbols. This creates a dangerous illusion of security: passwords like `Password123!` satisfy all composition rules yet are easily cracked by automated dictionary and mask attacks.

**DefendPass** implements an **in-memory, defensive cybersecurity engine** that evaluates password strength holistically:

$$\text{Password Strength} = \text{Length} + \text{Unpredictability} + \text{Pattern Resistance} + \text{Common-Password Screening} + \text{Context Awareness}$$

The application provides real-time diagnostics, educational comparisons of theoretical vs. effective entropy, a NIST SP 800-63B policy auditor, a cryptographically secure random password/passphrase studio, and an aggregate telemetry dashboard that records **zero passwords or hashes**.

---

## Problem Statement

According to the Verizon Data Breach Investigations Report (DBIR), over 80% of web application breaches involve compromised or weak credentials. While enterprise policies have historically enforced syntactic complexity, this has backfired:
1. Users adopt predictable patterns (capital letter at the start, dictionary word in the middle, `123` or current year at the end, trailing symbol).
2. Cracking engines (Hashcat, John the Ripper) specifically optimize hybrid mask attacks to exploit these exact human tendencies.
3. Legacy strength meters give false reassurance to vulnerable passwords, failing to detect keyboard walks (`qwerty`), numeric runs (`1234`), or breached wordlist entries.

---

## Objectives

- **Defensive Evaluation**: Provide a 100% defensive tool to analyze candidate passwords locally without offensive cracking or credential harvesting.
- **Pattern & Walk Detection**: Detect ascending/descending numeric and alphabetical runs, physical QWERTY keyboard walks, repetitive syllables, and common composition formulas.
- **Entropy Education**: Implement Shannon theoretical entropy alongside effective penalized entropy to demonstrate why composition without randomness is vulnerable.
- **Actionable Remediation**: Deliver specific remediation steps and promote memorable multi-word passphrases (Diceware / EFF model) as user-friendly alternatives.
- **Enterprise Policy Auditing**: Evaluate credentials against modern NIST SP 800-63B principles, contrasting policy compliance with true cryptographic strength.
- **Zero-Credential Privacy Design**: Ensure through software architecture and automated tests that submitted passwords exist solely in ephemeral memory and cannot leak to logs, disk, or databases.

---

## Cybersecurity Relevance

Password security controls are critical across enterprise and consumer digital ecosystems:

- **Identity & Access Management (IAM)**: Real-time validation of registration passwords; preventing users from creating high-risk predictable credentials.
- **Application Security (AppSec)**: Secure authentication architecture; implementing memory-hard salted hashing (Argon2id, scrypt, bcrypt) and avoiding plaintext logging.
- **Security Operations Center (SOC)**: Understanding how credential stuffing, password spraying, and dictionary attacks operate to craft SIEM detection rules.
- **Compliance & Governance**: Aligning enterprise password policies with modern NIST SP 800-63B, ISO 27001, and GDPR Article 5(1)(c) data minimization standards.

---

## Features

- **Real-Time Password Diagnostics**: Instant debounced evaluation displaying a 0–100 score, classification (`VERY WEAK`, `WEAK`, `MODERATE`, `STRONG`, `VERY STRONG`), and letter grade.
- **Multi-Vector Pattern Detection**:
  - Ascending & descending numeric sequences (`1234`, `9876`)
  - Ascending & descending alphabetical runs (`abcd`, `dcba`)
  - Physical QWERTY keyboard row and diagonal walks (`qwerty`, `asdf`, `1qaz`)
  - Repetitive characters (`aaaa`) and multi-character blocks (`ababab`, `abcabc`)
  - Predictable formulas (`TitleWord + Digits + Symbol`) and four-digit calendar years
  - Optional voluntary personal context overlap (first name, birth year, organization)
- **Common Password Screening**: Fast $O(1)$ set lookup against a curated list of over 200 common passwords.
- **Entropy Comparison**: Theoretical Shannon bits vs. penalized effective bits with educational caveats.
- **Actionable Suggestions Engine**: Specific remediation guidance without echoing or leaking the user's password.
- **NIST SP 800-63B Policy Checker**: Real-time compliance auditing highlighting the distinction between policy compliance and true strength.
- **Key & Passphrase Studio**: Cryptographically secure random password generator and memorable 4-to-6 word passphrase studio using Python's `secrets` module (OS-level CSPRNG).
- **Privacy-Preserving Dashboard**: SQLite-backed aggregate telemetry and Chart.js charts showing score, classification, and weakness distributions with **zero credential storage**.
- **Educational Cryptographic Hashing Lab**: Demonstrates salted PBKDF2-HMAC-SHA256 and scrypt with constant-time verification.

---

## Architecture

The system operates on an **ephemeral in-memory pipeline**:

```
[User Browser Interface]
         │
         ▼ (Debounced HTTP POST /api/analyze)
[Flask API Boundary]
         │
         ▼ (In-Memory Ephemeral Pipeline)
┌────────────────────────────────────────────────────────┐
│ Length & Depth Analyzer                                │
│ Character Diversity & Uniqueness Ratio Analyzer        │
│ Common Password Set Screening (O(1) Hash Set)          │
│ Contiguous Sequence Detector (Asc/Desc runs)           │
│ Physical QWERTY Keyboard Walk Detector                 │
│ Repetition & Syllable Block Detector                   │
│ Voluntary Personal Context Overlap Detector            │
│ Shannon Theoretical & Effective Entropy Estimator      │
└────────────────────────────────────────────────────────┘
         │
         ▼
[Defensive Strength Scoring Engine (0-100 Weighted & Penalized)]
         │
         ├────────────────────────────────────────┬──────────────────────────────────┐
         ▼                                        ▼                                  ▼
[Remediation Suggestions]              [NIST Policy Compliance]            [Safe Analytics Telemetry]
         │                                        │                                  │
         ▼ (JSON Response)                        ▼                                  ▼
[User Browser Interface]               [Policy View]                       [SQLite: analytics.db]
                                                                            (NO Passwords / Hashes)
```

---

## Technology Stack

- **Backend**: Python 3.11, Flask, Flask-CORS, SQLite3.
- **Frontend**: HTML5, Vanilla CSS3 (Custom Cyberpunk Glassmorphism Design System, CSS Variables), JavaScript ES6+ (Debouncing, Fetch API).
- **Data Visualization**: Chart.js 4.x for dynamic canvas charts.
- **Cryptographic Primitives**: Standard library `secrets` (OS CSPRNG: `BCryptGenRandom` on Windows, `/dev/urandom` on POSIX), `hashlib.pbkdf2_hmac`, `hashlib.scrypt`, `hmac.compare_digest`.
- **Testing**: `pytest` 9.x.

---

## Password Analysis

DefendPass orchestrates password analysis through `backend/services/password_analyzer.py`. When a candidate password is submitted, it is processed transiently in runtime memory through six analytical modules before returning a structured JSON payload:

```json
{
  "score": 74,
  "classification": "STRONG",
  "color": "#10b981",
  "grade": "B",
  "findings": [...],
  "suggestions": {
    "immediate_actions": [...],
    "passphrase_tip": "...",
    "hygiene_recommendations": [...]
  },
  "metrics": {
    "length": { "length": 16, "band": "Strong Length (16+ chars)", "status": "excellent" },
    "characters": { "lowercase": 8, "uppercase": 4, "digits": 2, "symbols": 2, "unique_character_ratio": 0.88 },
    "entropy": { "theoretical_bits": 91.2, "effective_bits": 82.5, "pool_size": 94 },
    "is_common": false
  }
}
```

---

## Length Analysis

Length provides exponential keyspace depth ($N^L$). DefendPass classifies length into educational bands:
- **< 8 Characters**: *Very Short* — Trivial search space; penalized down to VERY WEAK.
- **8–11 Characters**: *Short* — Acceptable only if completely random; vulnerable to mask attacks.
- **12–15 Characters**: *Good Length* — Solid baseline recommended by modern standards.
- **16+ Characters**: *Strong Length* — Expands keyspace depth beyond offline recovery budgets.

*Important Note*: Length alone does not guarantee security. A password like `aaaaaaaaaaaaaaaa` has length 16, but its keyspace is virtually nonexistent.

---

## Pattern Detection

Located in `backend/services/pattern_detector.py`:
- **Numeric Sequences**: Detects runs of $\ge 3$ consecutive digits where $\Delta = \pm 1$ (e.g., `1234`, `9876`).
- **Alphabetical Sequences**: Detects runs of $\ge 4$ consecutive letters in lexicographical order (e.g., `abcd`, `dcba`).
- **Keyboard Walks**: Models physical QWERTY rows and diagonal walks (`qwerty`, `asdfgh`, `zxcvbnm`, `1qaz`).
- **Repetitive Syllables**: Flags consecutive repeating characters (`aaaa`) and repeated pattern blocks (`ababab`, `abcabc`).
- **Predictable Formulas**: Detects `TitleWord + Digits + Symbol` (e.g., `Password123!`) and four-digit calendar years (`2024`, `2025`, `2026`).
- **Personal Context Overlap**: Checks voluntary demo inputs (name, birth year, organization) in raw or leetspeak form.

---

## Common Password Detection

Maintains an in-memory hash set of high-frequency common passwords loaded from `data/common_passwords.txt`. Lookups execute in $O(1)$ time. If matched:
- A critical finding is triggered.
- A 40-point penalty is deducted.
- The score is capped at $\le 15$ (`VERY WEAK`), preventing known breached credentials from earning false high scores.

---

## Entropy Estimation

Theoretical Shannon entropy represents the logarithm base 2 of the uniform search space:

$$E_{\text{theoretical}} = L \times \log_2(N)$$

where $L$ is length and $N$ is pool size (lowercase=26, uppercase=26, digits=10, symbols=32).

**Why raw theoretical entropy is misleading**: Theoretical entropy assumes every character is chosen independently and uniformly at random. Human passwords follow dictionary words and keyboard layouts. A password like `Password123!` has $L=12, N=94$, giving a naive theoretical entropy of $\approx 78.6\text{ bits}$. In reality, its effective search space against dictionary rules is only $\approx 15\text{--}20\text{ bits}$. DefendPass computes an **Effective Entropy** metric that applies structural penalty ratios when patterns or repetitions are detected.

---

## Strength Scoring

Scores range from **0 to 100** using positive contributions and severe deductions:
- **Bonuses**: Length (up to +35), Diversity (up to +15), Unique Ratio (up to +10), Pattern Resistance (up to +20), Non-Common (up to +10), Effective Entropy (up to +10).
- **Deductions**: Common password (-40 & cap $\le 15$), Keyboard walk (-15), Sequences (-12), Repetition (-12), Predictable formula (-15), Predictable year (-10), Personal context (-25).
- **Calibration Bands**:
  - `0–20`: **VERY WEAK** (Red)
  - `21–40`: **WEAK** (Orange)
  - `41–60`: **MODERATE** (Yellow)
  - `61–80`: **STRONG** (Light Green)
  - `81–100`: **VERY STRONG** (Emerald)

---

## Security Suggestions

The suggestion engine (`backend/services/suggestion_engine.py`) generates actionable advice:
- Priority remediations for detected patterns.
- Memorable multi-word passphrase recommendations.
- Universal hygiene guidelines (Password managers, MFA, Credential uniqueness, AiTM phishing awareness).
- **Defensive Privacy Guarantee**: The user's entered password is **never echoed or quoted** in recommendation text.

---

## Password Generator

Built with Python's standard `secrets` module (never `random`):
- **CSPRNG Password Mode**: Generates 8-to-32 character passwords, guarantees presence of at least one character from each selected class, and shuffles with `secrets.SystemRandom`.
- **Passphrase Studio Mode**: Generates 4-to-6 word passphrases from a safe, memorable wordlist joined by configurable separators (`-`, `.`, `_`, space).
- Generated credentials are never logged or stored.

---

## Password Policy Checker

Evaluates passwords against modern **NIST SP 800-63B** principles:
- Minimum length of 12 characters.
- Maximum length threshold (up to 128 characters).
- Screening against common password blocklists.
- Screening for personal identifying context.
- Permitting whitespace for passphrases.

*Compliance vs. Strength*: The interface educates users that a password can pass a legacy policy (e.g. `Password123!`) while being predictable, or fail rigid rules while possessing high entropy (e.g. a 25-character lowercase passphrase).

---

## Privacy Design

DefendPass is built from the ground up on **Privacy-by-Design** and **Data Minimization** (GDPR Art. 5(1)(c)):
1. **In-Memory Ephemeral Analysis**: Passwords exist solely in volatile runtime memory during evaluation and are garbage-collected immediately.
2. **Zero Password Logging**: HTTP request bodies are never written to access logs.
3. **Database Schema Guarantee**: `analytics.db` contains **zero password columns** and **zero hash columns**.
4. **Local Execution**: No passwords or metadata are ever transmitted to third-party APIs.

---

## Installation

### Prerequisites
- Python 3.10+ (Python 3.11 recommended)
- Modern web browser (Chrome, Edge, Firefox, Brave)

### Setup Steps
```bash
# 1. Clone repository
git clone https://github.com/your-username/Password-Strength-Analyzer-Security-Tool.git
cd Password-Strength-Analyzer-Security-Tool

# 2. (Optional) Create virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### 1. Start Application Server
```bash
python -m backend.app
```
*Console output:*
```
================================================================================
 [DEFENDPASS] PASSWORD STRENGTH ANALYZER & SECURITY SUGGESTION TOOL (DEFENSIVE) 
================================================================================
 -> Server running locally at: http://127.0.0.1:5000/
 -> Privacy Guarantee: No passwords or hashes are logged or stored.
 -> Defensive Mode: Active (Local in-memory evaluation only)
================================================================================
```

### 2. Access Web Interface
Open your web browser and navigate to:
```
http://127.0.0.1:5000/
```

### 3. Run Standalone Hashing Demonstration
```bash
python backend/utils/hashing_demo.py
```

---

## API Documentation

### 1. Transient Password Analysis
- **Endpoint**: `POST /api/analyze`
- **Headers**: `Content-Type: application/json`
- **Request Body**:
  ```json
  {
    "password": "SampleCandidatePassword123!",
    "context": {
      "firstName": "Alice",
      "birthYear": "2001",
      "companyName": "CyberCorp"
    },
    "save_analytics": true
  }
  ```
- **Response**: Status `200 OK` with JSON diagnostics (score, classification, findings, suggestions, metrics).

### 2. CSPRNG Password Generation
- **Endpoint**: `POST /api/generate-password`
- **Request Body**: `{"length": 20, "use_upper": true, "use_lower": true, "use_digits": true, "use_symbols": true}`
- **Response**: `{"status": "success", "data": {"password": "...", "length": 20}}`

### 3. Memorable Passphrase Generation
- **Endpoint**: `POST /api/generate-passphrase`
- **Request Body**: `{"word_count": 4, "separator": "-", "capitalize": true}`
- **Response**: `{"status": "success", "data": {"passphrase": "...", "word_count": 4}}`

### 4. Privacy Analytics Stats
- **Endpoint**: `GET /api/dashboard/stats`
- **Response**: Anonymous aggregate metrics (total analyses, average score, classification distribution).

---

## Testing

Execute the automated test suite with pytest:
```bash
pytest -v tests/
```

Test suite coverage includes:
- Boundary conditions (empty, single-character, max length)
- Character class variations (lower only, upper only, digits only, symbols only, mixed)
- Pattern detectors (ascending/descending numbers, alphabetical sequences, keyboard walks, repetitions)
- Contextual personal info overlap
- CSPRNG password and passphrase generators
- Scoring engine bounds and classification bands

---

## Security Testing

Automated privacy assertions in `tests/test_security_privacy.py` verify:
1. **Schema Inspection**: SQLite table PRAGMA asserts no `password`, `plaintext`, or `hash` columns exist.
2. **Zero Leakage**: Asserts the exact submitted password never appears in suggestions, findings, or error payloads.
3. **Storage Minimization**: Asserts database records contain only numerical/categorical metadata.
4. **Input Sanitization**: Verifies rejection of non-JSON payloads and oversized (>512 chars) inputs.

---

## Results

Evaluation across synthetic test credentials:

| Test Password | Identified Weaknesses | Score | Classification |
| :--- | :--- | :---: | :---: |
| `123456` | Common password, Ascending digits | **0** | **VERY WEAK** |
| `Password123!` | Common password, Predictable formula (Word+Num+Sym) | **0** | **VERY WEAK** |
| `aaaaaaaaaaaaaaaa` | Repeated characters, Low uniqueness ratio | **31** | **WEAK** |
| `qwerty2026!` | Keyboard walk, Four-digit year | **25** | **WEAK** |
| `Orbit-Cobalt-Lantern-Glacier` | None detected | **91** | **VERY STRONG** |
| `mK8#vL2$pQ9*wZ4!jX7&` | None detected | **100** | **VERY STRONG** |

---

## Limitations

- **No Absolute Formula**: Password strength cannot be perfectly quantified by any single numerical formula. Attacker capabilities and GPU investments vary.
- **Curated Common List**: Uses an educational corpus (~250 words). Production enterprise systems integrate larger bloom filters (e.g. Have I Been Pwned via k-Anonymity).
- **QWERTY Focus**: Keyboard walk modeling is calibrated to the standard US QWERTY physical layout.

---

## Future Improvements

- **k-Anonymity Breach Screening**: Query the Have I Been Pwned API using SHA-1 5-character hash prefixes without exposing the user's password.
- **Multi-Layout Support**: Expand keyboard walk graphs to AZERTY and QWERTZ layouts.
- **WebAuthn Passkey Simulator**: Educational module illustrating FIDO2 public-key authentication ceremonies.
- **Dynamic Zxcvbn Modeling**: Dictionary matching across multiple language corpuses.

---

## Screenshots

Visual documentation and screenshot guides are cataloged in [`screenshots/README.md`](screenshots/README.md).

---

## Learning Outcomes

- Mastery of modern password authentication, salted hashing, and Key Derivation Functions (Argon2id, scrypt, PBKDF2).
- Practical implementation of Privacy-by-Design and data minimization principles.
- Experience building defensive pattern detection algorithms and entropy models.
- Deep understanding of modern digital identity guidelines (NIST SP 800-63B).

---

## Security Disclaimer

This project is created strictly for **defensive, educational, and academic purposes**. It does not harvest credentials, attempt unauthorized logins, or perform password cracking. All testing is conducted using synthetic demonstration passwords. Never reuse demonstration passwords for real-world accounts.

---

## Author

**Cybersecurity Engineering Student**  
- **Focus**: Application Security, IAM, Defensive Cybersecurity, Python Development  
- **GitHub**: [Your Profile Link]  
- **LinkedIn**: [Your Profile Link]  
