"""
Automated Unit Tests for Password Analyzer Engine
Covers all 27+ core functional analysis and edge scenarios.
"""
import pytest
from backend.services.password_analyzer import analyze_password, analyze_length, analyze_characters, check_common_password
from backend.services.pattern_detector import (
    detect_numeric_sequences,
    detect_alphabetical_sequences,
    detect_keyboard_patterns,
    detect_repetition,
    detect_predictable_structure,
    detect_personal_context
)
from backend.services.entropy_estimator import estimate_theoretical_entropy
from backend.services.password_generator import generate_secure_password, generate_secure_passphrase
from backend.services.policy_checker import check_password_policy

# Test 1: Empty password
def test_01_empty_password():
    result = analyze_password("")
    assert result["score"] == 0
    assert result["metrics"]["length"]["length"] == 0
    assert result["classification"] in ("VERY WEAK", "NO INPUT")

# Test 2: One-character password
def test_02_one_character_password():
    result = analyze_password("a")
    assert result["score"] <= 20
    assert result["classification"] == "VERY WEAK"
    assert result["metrics"]["length"]["length"] == 1

# Test 3: Short numeric password
def test_03_short_numeric_password():
    result = analyze_password("8392")
    assert result["score"] <= 20
    assert result["classification"] == "VERY WEAK"
    assert result["metrics"]["characters"]["digits"] == 4

# Test 4: Common password
def test_04_common_password():
    result = analyze_password("password")
    assert result["metrics"]["is_common"] is True
    assert result["classification"] == "VERY WEAK"
    assert any(f["type"] == "common_password" for f in result["findings"])

# Test 5: Long repeated password (e.g. 16 'a's)
def test_05_long_repeated_password():
    result = analyze_password("aaaaaaaaaaaaaaaa")
    # Despite length 16, repetitive nature must prevent it from being STRONG
    assert result["score"] < 50
    assert result["classification"] in ("VERY WEAK", "WEAK")
    assert any(f["type"] == "repeated_characters" for f in result["findings"])

# Test 6: Lowercase only
def test_06_lowercase_only():
    chars = analyze_characters("abcdefghijkl")
    assert chars["lowercase"] == 12
    assert chars["uppercase"] == 0
    assert chars["digits"] == 0
    assert chars["symbols"] == 0
    assert chars["character_types_present"] == 1

# Test 7: Uppercase only
def test_07_uppercase_only():
    chars = analyze_characters("ABCDEFGHIJKL")
    assert chars["uppercase"] == 12
    assert chars["character_types_present"] == 1

# Test 8: Numbers only
def test_08_numbers_only():
    chars = analyze_characters("928374619283")
    assert chars["digits"] == 12
    assert chars["character_types_present"] == 1

# Test 9: Symbols only
def test_09_symbols_only():
    chars = analyze_characters("!@#$%^&*()_+")
    assert chars["symbols"] == 12
    assert chars["character_types_present"] == 1

# Test 10: Mixed characters
def test_10_mixed_characters():
    chars = analyze_characters("Abc123!@#")
    assert chars["character_types_present"] == 4
    assert chars["lowercase"] > 0
    assert chars["uppercase"] > 0
    assert chars["digits"] > 0
    assert chars["symbols"] > 0

# Test 11: Sequential numbers (ascending)
def test_11_sequential_numbers_ascending():
    findings = detect_numeric_sequences("pass12345code")
    assert any(f["type"] == "numeric_sequence" and "ascending" in f["pattern"] for f in findings)

# Test 12: Reverse numeric sequence (descending)
def test_12_sequential_numbers_descending():
    findings = detect_numeric_sequences("pass98765code")
    assert any(f["type"] == "numeric_sequence" and "descending" in f["pattern"] for f in findings)

# Test 13: Sequential letters (ascending and descending)
def test_13_sequential_letters():
    findings_asc = detect_alphabetical_sequences("prefix_abcd_suffix")
    assert any(f["type"] == "alphabetical_sequence" for f in findings_asc)
    findings_desc = detect_alphabetical_sequences("prefix_dcba_suffix")
    assert any(f["type"] == "alphabetical_sequence" for f in findings_desc)

# Test 14: Keyboard sequence (QWERTY walk)
def test_14_keyboard_sequence():
    findings = detect_keyboard_patterns("my_qwerty_pass")
    assert any(f["type"] == "keyboard_pattern" for f in findings)

# Test 15: Repeated individual characters
def test_15_repeated_characters():
    findings = detect_repetition("helllooooWorld")
    assert any(f["type"] == "repeated_characters" for f in findings)

# Test 16: Repeated substring block
def test_16_repeated_substring():
    findings = detect_repetition("abcabcabc123")
    assert any(f["type"] == "repeated_substring" for f in findings)

# Test 17: Common word + predictable number
def test_17_common_word_number():
    result = analyze_password("welcome123")
    assert result["score"] <= 30
    assert any(f["type"] in ("common_password", "numeric_sequence") for f in result["findings"])

# Test 18: Word + Year pattern
def test_18_word_year_pattern():
    findings = detect_predictable_structure("Winter2025!")
    assert any(f["type"] == "predictable_year" for f in findings)

# Test 19: Personal name overlap (contextual check)
def test_19_personal_name_overlap():
    findings = detect_personal_context("RahulSecure123!", context={"firstName": "Rahul"})
    assert any(f["type"] == "personal_information" for f in findings)

# Test 20: Birth year overlap (contextual check)
def test_20_birth_year_overlap():
    findings = detect_personal_context("Pass2002Word!", context={"birthYear": "2002"})
    assert any(f["type"] == "personal_information" for f in findings)

# Test 21: Long passphrase-like input
def test_21_long_passphrase_input():
    result = analyze_password("correct-horse-battery-staple-2026")
    assert result["score"] >= 65
    assert result["classification"] in ("STRONG", "VERY STRONG")
    assert result["metrics"]["length"]["length"] > 20

# Test 22: Unicode character handling
def test_22_unicode_handling():
    result = analyze_password("Pässwørd123!🛡️")
    assert result["metrics"]["length"]["length"] > 0
    assert isinstance(result["score"], int)

# Test 23: Space character handling
def test_23_space_handling():
    chars = analyze_characters("my secure passphrase with spaces")
    assert chars["spaces"] == 4
    assert chars["character_types_present"] >= 1

# Test 24: Maximum accepted length boundary (e.g. 128 characters)
def test_24_maximum_length_boundary():
    long_pwd = "A" * 128
    result = analyze_password(long_pwd)
    assert result["metrics"]["length"]["length"] == 128

# Test 25: Strength-score boundaries [0, 100]
def test_25_score_boundaries():
    r1 = analyze_password("")
    assert 0 <= r1["score"] <= 100
    r2 = analyze_password("123456")
    assert 0 <= r2["score"] <= 100
    r3 = analyze_password("kX9#mQ2$vL8*pW4!jZ6&")
    assert 0 <= r3["score"] <= 100
    assert r3["score"] >= 80

# Test 26: Security suggestion generation
def test_26_suggestion_generation():
    result = analyze_password("123456")
    assert len(result["suggestions"]["immediate_actions"]) > 0
    assert len(result["suggestions"]["hygiene_recommendations"]) > 0

# Test 27: Cryptographically secure password generation
def test_27_secure_password_generator():
    gen1 = generate_secure_password(length=20)
    assert len(gen1["password"]) == 20
    assert any(c.isupper() for c in gen1["password"])
    assert any(c.islower() for c in gen1["password"])
    assert any(c.isdigit() for c in gen1["password"])
    
    gen2 = generate_secure_passphrase(word_count=5, separator="-")
    words = gen2["passphrase"].split("-")
    assert len(words) == 5
