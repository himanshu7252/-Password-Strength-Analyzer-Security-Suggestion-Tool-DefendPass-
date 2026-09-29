# Screenshot & Demonstration Verification Guide

This directory documents the visual evidence and demonstration test cases for the **Password Strength Analyzer & Security Suggestion Tool**.

## Recommended Screenshot Catalog

| Screenshot ID | Recommended Filename | Screen / Component | Demonstration Purpose |
| :--- | :--- | :--- | :--- |
| **SCR-01** | `01_project_structure.png` | Terminal / IDE File Tree | Demonstrates modular architecture (`backend`, `frontend`, `data`, `tests`, `docs`) |
| **SCR-02** | `02_architecture_diagram.png` | Architecture Workflow | Illustrates privacy-preserving in-memory data flow |
| **SCR-03** | `03_analyzer_homepage.png` | Full Application UI | Shows dark cyberpunk aesthetic, glassmorphic cards, and header badges |
| **SCR-04** | `04_hidden_password_field.png` | Input Bar | Shows masked password input (`type="password"`) with eye toggle |
| **SCR-05** | `05_test1_very_weak.png` | Analyzer Tab | Input `123456` displaying `VERY WEAK` (Red), score 0/100, common password warning |
| **SCR-06** | `06_test2_predictable_formula.png` | Analyzer Tab | Input `Password123!` showing composition diversity but predictable formula penalty |
| **SCR-07** | `07_test3_repetitive_weak.png` | Analyzer Tab | Input `aaaaaaaaaaaaaaaa` (16 chars) flagged for high repetition and low uniqueness |
| **SCR-08** | `08_test4_keyboard_walk.png` | Analyzer Tab | Input `qwerty2026!` displaying keyboard pattern and year deductions |
| **SCR-09** | `09_test5_passphrase_strong.png` | Analyzer Tab | Input `Orbit-Cobalt-Lantern-Glacier` showing `VERY STRONG` (Emerald) rating |
| **SCR-10** | `10_test6_random_csprng.png` | Analyzer Tab | Input 20-character random password generated via OS CSPRNG scoring 95-100 |
| **SCR-11** | `11_length_diversity_metrics.png` | Metric Quad Cards | Detailed view of length band, character classes, and uniqueness ratio |
| **SCR-12** | `12_entropy_calculation.png` | Metric Quad Cards | Theoretical vs effective entropy display with educational caveat |
| **SCR-13** | `13_context_personal_warning.png` | Analyzer Accordion | Context check flagging personal name/birth year overlap in password |
| **SCR-14** | `14_actionable_suggestions.png` | Suggestions Card | Remediation actions, passphrase advice, and hygiene guidelines |
| **SCR-15** | `15_policy_compliance_pass.png` | Policy Tab | Enterprise NIST SP 800-63B evaluation showing PASSED status |
| **SCR-16** | `16_policy_compliance_fail.png` | Policy Tab | Enterprise policy evaluation showing specific rule violations |
| **SCR-17** | `17_csprng_generator.png` | Generator Studio | Random password generator controls, length slider, and copy button |
| **SCR-18** | `18_passphrase_studio.png` | Generator Studio | Multi-word passphrase generator with customizable separators |
| **SCR-19** | `19_privacy_dashboard_overview.png`| Analytics Tab | Aggregate telemetry counters and zero-credential storage guarantee |
| **SCR-20** | `20_classification_chart.png` | Analytics Tab | Chart.js doughnut chart of strength classifications |
| **SCR-21** | `21_score_distribution_chart.png`| Analytics Tab | Chart.js bar chart of 20-point score buckets |
| **SCR-22** | `22_weakness_frequency_chart.png`| Analytics Tab | Chart.js horizontal bar chart of top identified patterns |
| **SCR-23** | `23_length_distribution_chart.png`| Analytics Tab | Chart.js distribution chart of password length bands |
| **SCR-24** | `24_awareness_10_rules.png` | Awareness Tab | 10 Golden Rules of modern password security timeline |
| **SCR-25** | `25_defense_in_depth_pillars.png` | Awareness Tab | Enterprise authentication pillars (MFA, Rate Limiting, Lockout, etc.) |
| **SCR-26** | `26_hashing_lab_matrix.png` | Hashing Lab Tab | Cryptographic algorithm comparison (MD5 vs SHA256 vs Argon2/scrypt) |
| **SCR-27** | `27_terminal_hashing_demo.png` | Terminal Output | Execution of `backend/utils/hashing_demo.py` (PBKDF2 & scrypt verification) |
| **SCR-28** | `28_pytest_33_passed.png` | Terminal Output | `pytest -v tests/` showing all 33 unit and privacy tests passing |
| **SCR-29** | `29_sqlite_schema_no_passwords.png`| SQLite Studio/CLI | `PRAGMA table_info(analyses);` proving absence of password columns |
| **SCR-30** | `30_github_repository.png` | GitHub Web | Clean repository layout, commit history, badges, and documentation |

## How to Capture Demonstration Proof Locally

1. **Launch the Application**:
   ```bash
   python -m backend.app
   ```
2. **Open Browser**:
   Navigate to `http://127.0.0.1:5000/`.
3. **Use Safe Demonstration Presets**:
   Click the preset buttons at the top of the analyzer to populate standard test passwords without manual typing.
4. **Inspect Database Schema**:
   In terminal:
   ```bash
   python -c "import sqlite3; conn = sqlite3.connect('backend/analytics.db'); print([r[1] for r in conn.execute('PRAGMA table_info(analyses)').fetchall()])"
   ```
   *Expected Output*: `['analysis_id', 'score', 'classification', 'password_length', 'unique_character_ratio', 'weakness_count', 'entropy_estimate', 'created_at']` (Notice: ZERO password or hash columns).
