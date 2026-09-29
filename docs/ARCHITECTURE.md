# System Architecture & Defensive Security Design

## 1. High-Level Architectural Overview

The **Password Strength Analyzer & Security Suggestion Tool** is architected as an **in-memory, privacy-preserving defensive evaluation system**. It decouples password strength assessment from persistent credential storage, ensuring zero risk of credential harvesting, leakage, or unnecessary attack surface creation.

```mermaid
flowchart TD
    User([User / Security Auditor]) -->|Enters Candidate Credential| WebUI[Secure Modern Web Interface\n(HTML5 / Vanilla CSS Glassmorphism / JS)]
    
    subgraph Frontend_Security_Boundary [Client-Side Layer]
        WebUI --> MaskInput[Masked Password Field (type='password')]
        WebUI --> Debounce[Input Debouncer (120ms)]
    end

    Debounce -->|Transient POST /api/analyze| APIServer[Flask Application Server\n(backend/app.py)]
    
    subgraph Backend_Ephemeral_Pipeline [In-Memory Ephemeral Analysis Pipeline]
        APIServer --> LengthEngine[Length Analyzer\n(Length Bands & Depth)]
        APIServer --> CharEngine[Character Diversity\n(Classes & Unique Ratio)]
        APIServer --> CommonChecker[Common Wordlist Checker\n(data/common_passwords.txt)]
        APIServer --> PatternEngine[Pattern & Walk Detector\n(Sequences, Walks, Repeats)]
        APIServer --> ContextEngine[Context Check\n(Voluntary Personal Info)]
        APIServer --> EntropyEngine[Entropy Estimator\n(Theoretical vs Effective Bits)]
        
        LengthEngine & CharEngine & CommonChecker & PatternEngine & ContextEngine & EntropyEngine --> ScoreEngine[Defensive Scoring Engine\n(0-100 Weighted & Penalized)]
        
        ScoreEngine --> SuggestionEngine[Remediation & Hygiene Engine]
        ScoreEngine --> PolicyEngine[NIST SP 800-63B Policy Checker]
    end

    SuggestionEngine & PolicyEngine -->|JSON Diagnostic Payload| WebUI
    
    subgraph Privacy_Preserving_Storage [Privacy-Preserving Telemetry]
        ScoreEngine -.->|Safe Anonymous Aggregates ONLY\n(score, length, weakness_type)| SQLite[(analytics.db\nNO Password or Hash Columns)]
    end

    SQLite -.->|GET /api/dashboard/stats| DashView[Interactive Chart.js Dashboard]
```

---

## 2. Component Breakdown & Responsibilities

| Component | File Path | Primary Responsibility | Defensive Guarantee |
| :--- | :--- | :--- | :--- |
| **Primary App Server** | `backend/app.py` | Serves web assets, exposes REST APIs, suppresses HTTP body logging. | Request bodies containing credentials are never written to disk or logs. |
| **Core Analyzer** | `backend/services/password_analyzer.py` | Orchestrates transient evaluation pipeline. | Input variable is ephemeral in-memory; released upon function return. |
| **Pattern Detector** | `backend/services/pattern_detector.py` | Detects numeric sequences, alphabetical sequences, QWERTY walks, repetitive blocks, and year formulas. | Identifies structural predictability without storing pattern inputs. |
| **Entropy Estimator** | `backend/services/entropy_estimator.py` | Calculates theoretical entropy ($L \times \log_2(N)$) and effective entropy. | Educates users on why raw math overestimates human passwords. |
| **Scoring Engine** | `backend/services/scoring_engine.py` | Calibrates transparent 0-100 score with bonuses and heavy predictability penalties. | Restricts passwords under 8 chars to VERY WEAK regardless of character diversity. |
| **Suggestion Engine** | `backend/services/suggestion_engine.py` | Generates actionable remediation steps and passphrase alternatives. | Never echoes or quotes the user's password in output text. |
| **Policy Checker** | `backend/services/policy_checker.py` | Evaluates compliance against NIST SP 800-63B inspired enterprise rules. | Differentiates policy compliance from genuine cryptographic strength. |
| **CSPRNG Generator** | `backend/services/password_generator.py` | Generates secure passwords and passphrases using Python `secrets`. | Utilizes OS CSPRNG (`BCryptGenRandom` / `/dev/urandom`); never deterministic PRNGs. |
| **Analytics Model** | `backend/models/database.py` | Records safe mathematical aggregates in SQLite. | **Zero password column schema**: Impossible to store plaintext or hashed passwords. |
| **Hashing Lab** | `backend/utils/hashing_demo.py` | Educational module demonstrating salted PBKDF2 and scrypt hashing. | Isolated demo; never integrates arbitrary analyzer inputs into persistence. |

---

## 3. Ephemeral In-Memory Pipeline Flow

When a user types a password:

1. **Client-Side Debouncing**: The `input` listener waits 120ms to prevent superfluous network bursts.
2. **Encrypted Transport**: In production, HTTPS (TLS 1.3) protects the payload in flight. Locally, transport occurs via loopback (`127.0.0.1`).
3. **Ephemeral Memory Processing**:
   - The string is received by `analyzer_endpoint()`.
   - Length, character counts, and unique ratios are calculated in $O(N)$ time.
   - Fast $O(1)$ set lookup checks against `data/common_passwords.txt`.
   - Regular expressions scan for keyboard rows, diagonals, repeated characters, and predictable formulas.
   - Entropy is calculated via Shannon-Hartley logarithmic pool analysis.
   - Scoring engine aggregates bonuses (+length, +diversity, +uniqueness) and subtracts penalties (-sequences, -walks, -years, -common).
4. **Structured JSON Response**: The server sends back score, classification, findings, and suggestions.
5. **Garbage Collection**: The password string object loses all references in Python memory and is reclaimed by the garbage collector.
6. **Anonymous Telemetry (Optional)**: If enabled, only the numeric score, classification string, password length, uniqueness ratio, and identified weakness labels are stored in `analytics.db`.

---

## 4. Threat Modeling (STRIDE Analysis)

| Threat Category | Potential Threat in Password Tools | DefendPass Architectural Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates legitimate analyzer to harvest credentials. | Tool designed for self-hosted local deployment; full open-source auditability; zero external telemetry endpoints. |
| **Tampering** | Man-in-the-middle modifies analysis rules or response recommendations. | Transport over TLS in network deployment; local loopback execution; constant rule definitions in code. |
| **Repudiation** | Disputes over aggregate compliance audits. | Anonymous analytical telemetry timestamped in `analytics.db` without storing user identities. |
| **Information Disclosure** | Passwords stored in databases, logs, or leaked via error traces. | **Defensive by Design**: No database columns exist for passwords or hashes. Request body logging is suppressed. |
| **Denial of Service** | Oversized payloads (e.g. 10MB string) exhausting server CPU. | Request validator enforces a strict 512-character maximum threshold; returns HTTP 400 immediately for oversized inputs. |
| **Elevation of Privilege** | Code execution via injection in custom context fields. | Parameterized queries for all SQLite interactions; strict string typing; zero `eval()` or OS shell executions. |

---

## 5. Technology Stack Evaluation

### Backend: Python 3.11 + Flask
- **Rationale**: Python provides native access to standard cryptographic libraries (`secrets`, `hashlib.pbkdf2_hmac`, `hashlib.scrypt`). Flask provides a lightweight, transparent microframework with zero bloat, ideal for security auditing and educational demonstration.

### Frontend: Vanilla HTML5, CSS3, & Modern JavaScript (ES6+)
- **Rationale**: Zero external framework build steps (no complex Node.js/Webpack build chain required for evaluation). Delivers instant local startup, rock-solid reliability on any student machine, and ultra-high aesthetic quality with native CSS variables and glassmorphism.

### Data Visualization: Chart.js
- **Rationale**: Lightweight, accessible, canvas-based rendering for high-performance dashboard charts without tracking or external telemetry.

### Analytics Storage: SQLite3
- **Rationale**: Embedded zero-configuration ACID database. Ensures the student does not need to configure external database daemons (like PostgreSQL or MySQL) while demonstrating relational schema design and SQL aggregate queries.
