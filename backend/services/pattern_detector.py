"""
Pattern Detector Service
Analyzes passwords for predictable sequences, keyboard patterns, repetitions,
predictable structures (word + year), and voluntary personal context overlap.
"""
import re
from typing import List, Dict, Any, Optional

# Standard QWERTY keyboard sequences for walk detection
KEYBOARD_ROWS = [
    "`1234567890-=",
    "~!@#$%^&*()_+",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]

KEYBOARD_DIAGONALS = [
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", "8ik,", "9ol.", "0p;/"
]

def detect_numeric_sequences(password: str, min_len: int = 3) -> List[Dict[str, Any]]:
    """
    Detect ascending or descending numeric sequences of at least `min_len` digits.
    Example: 1234, 5678, 9876, 4321.
    """
    findings = []
    digits_found = []
    
    # Extract contiguous digit segments
    for match in re.finditer(r'\d+', password):
        segment = match.group(0)
        if len(segment) < min_len:
            continue
        
        # Check ascending / descending inside the segment
        for i in range(len(segment) - min_len + 1):
            sub = segment[i:i + min_len]
            # Check ascending
            is_asc = all(int(sub[j + 1]) == (int(sub[j]) + 1) % 10 for j in range(len(sub) - 1))
            # Check descending
            is_desc = all(int(sub[j + 1]) == (int(sub[j]) - 1) % 10 for j in range(len(sub) - 1))
            
            if is_asc or is_desc:
                seq_type = "ascending" if is_asc else "descending"
                findings.append({
                    "type": "numeric_sequence",
                    "severity": "medium",
                    "pattern": f"{seq_type} digits",
                    "description": f"Predictable {seq_type} numeric sequence detected."
                })
                break  # Record once per continuous segment
    return findings

def detect_alphabetical_sequences(password: str, min_len: int = 4) -> List[Dict[str, Any]]:
    """
    Detect ascending or descending alphabetical sequences.
    Example: abcd, bcde, dcba, hgfe.
    """
    findings = []
    lower_pwd = password.lower()
    
    # Extract contiguous alpha segments
    for match in re.finditer(r'[a-z]+', lower_pwd):
        segment = match.group(0)
        if len(segment) < min_len:
            continue
        
        for i in range(len(segment) - min_len + 1):
            sub = segment[i:i + min_len]
            codes = [ord(c) for c in sub]
            is_asc = all(codes[j + 1] - codes[j] == 1 for j in range(len(codes) - 1))
            is_desc = all(codes[j] - codes[j + 1] == 1 for j in range(len(codes) - 1))
            
            if is_asc or is_desc:
                seq_type = "ascending" if is_asc else "descending"
                findings.append({
                    "type": "alphabetical_sequence",
                    "severity": "medium",
                    "pattern": f"{seq_type} alphabetical sequence",
                    "description": f"Predictable {seq_type} alphabetical sequence detected."
                })
                break
    return findings

def detect_keyboard_patterns(password: str, min_len: int = 4) -> List[Dict[str, Any]]:
    """
    Detect horizontal or diagonal keyboard walks across standard QWERTY layout.
    Example: qwerty, asdfgh, zxcv, 1qaz.
    """
    findings = []
    lower_pwd = password.lower()
    
    detected = False
    # Check rows (forward and reverse)
    for row in KEYBOARD_ROWS:
        rev_row = row[::-1]
        for pattern_len in range(min_len, 7):
            for i in range(len(row) - pattern_len + 1):
                chunk = row[i:i + pattern_len]
                if chunk in lower_pwd:
                    findings.append({
                        "type": "keyboard_pattern",
                        "severity": "high",
                        "pattern": "keyboard row walk",
                        "description": "Common keyboard sequence detected (such as QWERTY or ASDF walk)."
                    })
                    detected = True
                    break
                chunk_rev = rev_row[i:i + pattern_len]
                if chunk_rev in lower_pwd:
                    findings.append({
                        "type": "keyboard_pattern",
                        "severity": "high",
                        "pattern": "reversed keyboard row walk",
                        "description": "Reversed keyboard sequence detected."
                    })
                    detected = True
                    break
            if detected:
                break
        if detected:
            break
            
    # Check diagonals if not already flagged
    if not detected:
        for diag in KEYBOARD_DIAGONALS:
            rev_diag = diag[::-1]
            if diag in lower_pwd or rev_diag in lower_pwd:
                findings.append({
                    "type": "keyboard_pattern",
                    "severity": "medium",
                    "pattern": "keyboard diagonal walk",
                    "description": "Predictable keyboard column/diagonal pattern detected."
                })
                break

    return findings

def detect_repetition(password: str) -> List[Dict[str, Any]]:
    """
    Detect repeated individual characters (>=3) and repeated multi-character blocks (>=2 repeats).
    Example: aaaa, 1111, ababab, abcabc.
    """
    findings = []
    
    # 1. Repeated single character (>= 3 in a row)
    if re.search(r'(.)\1{2,}', password):
        findings.append({
            "type": "repeated_characters",
            "severity": "medium",
            "pattern": "consecutive identical characters",
            "description": "Multiple consecutive identical characters detected (e.g., 'aaa' or '111')."
        })
        
    # 2. Repeated multi-character substring (e.g., abab, 1212, abcabc)
    # Using regex to find 2-4 character patterns repeated at least twice consecutively
    match_chunk = re.search(r'(.{2,4})\1{1,}', password)
    if match_chunk:
        findings.append({
            "type": "repeated_substring",
            "severity": "medium",
            "pattern": "repeated pattern block",
            "description": "Repeated multi-character block pattern detected (e.g., 'abab' or 'abcabc')."
        })
        
    return findings

def detect_predictable_structure(password: str) -> List[Dict[str, Any]]:
    """
    Detect common composition formulas such as:
    - Common word followed by year (e.g., 1980-2035)
    - Common word followed by simple numbers (e.g., Summer123, Admin123!)
    - Trailing exclamation marks or single trailing symbols
    """
    findings = []
    
    # 1. Year pattern (1950 - 2035)
    year_match = re.search(r'(19[5-9]\d|20[0-3]\d)', password)
    if year_match:
        findings.append({
            "type": "predictable_year",
            "severity": "medium",
            "pattern": "four-digit year",
            "description": "Password contains a four-digit year pattern, which is easily targeted in dictionary/rule-based guessing."
        })
        
    # 2. Capitalized word + trailing digits + trailing symbol
    # Example: Password123!, Welcome2026#, Secret1!
    if re.match(r'^[A-Z][a-z]{3,}\d{1,4}[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/]$', password):
        findings.append({
            "type": "predictable_formula",
            "severity": "high",
            "pattern": "CapitalizedWord + Digits + Symbol",
            "description": "Password strictly matches the highly predictable 'TitleWord + Number + SpecialChar' template."
        })
        
    return findings

def detect_personal_context(password: str, context: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """
    Optionally check if voluntarily provided non-sensitive demo context appears in password.
    Context keys: firstName, birthYear, companyName, collegeName.
    NOTE: Values are never logged or stored. Comparisons are in-memory transient checks.
    """
    findings = []
    if not context:
        return findings
        
    lower_pwd = password.lower()
    
    # Simple leet substitution dictionary for fuzzy checking
    leet_map = {'@': 'a', '4': 'a', '3': 'e', '1': 'i', '0': 'o', '$': 's', '5': 's', '7': 't'}
    normalized_pwd = lower_pwd
    for char, repl in leet_map.items():
        normalized_pwd = normalized_pwd.replace(char, repl)
    
    for key, value in context.items():
        if not value or not isinstance(value, str):
            continue
        cleaned_val = value.strip().lower()
        if len(cleaned_val) < 3:
            continue
            
        if cleaned_val in lower_pwd or cleaned_val in normalized_pwd:
            human_label = {
                "firstName": "personal name",
                "first_name": "personal name",
                "name": "personal name",
                "birthYear": "birth year",
                "birth_year": "birth year",
                "company": "organization name",
                "companyName": "organization name",
                "college": "institution name",
                "collegeName": "institution name",
            }.get(key, "personal context")
            
            findings.append({
                "type": "personal_information",
                "severity": "critical",
                "pattern": f"contains {human_label}",
                "description": f"Password appears to include {human_label} from your context. Attackers routinely harvest personal info for targeted attacks."
            })
            
    return findings

def run_all_pattern_checks(password: str, context: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """
    Executes all pattern detectors and returns an aggregated list of unique findings.
    """
    if not password:
        return []
        
    findings = []
    findings.extend(detect_numeric_sequences(password))
    findings.extend(detect_alphabetical_sequences(password))
    findings.extend(detect_keyboard_patterns(password))
    findings.extend(detect_repetition(password))
    findings.extend(detect_predictable_structure(password))
    findings.extend(detect_personal_context(password, context))
    
    return findings
