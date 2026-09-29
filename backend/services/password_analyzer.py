"""
Password Analyzer Service (Core Engine)
Orchestrates length analysis, character diversity, common password detection,
pattern detection, entropy estimation, strength scoring, and suggestions.

DEFENSIVE ARCHITECTURE GUARANTEE:
Passwords are treated as ephemeral sensitive data. They are evaluated strictly
in-memory and NEVER logged, persisted, or cached.
"""
import os
import string
from typing import Dict, Any, Optional, Set

from .pattern_detector import run_all_pattern_checks
from .entropy_estimator import estimate_theoretical_entropy
from .scoring_engine import calculate_strength
from .suggestion_engine import generate_suggestions
from .policy_checker import check_password_policy

# Path to common passwords file
COMMON_PASSWORDS_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "common_passwords.txt")
)

_COMMON_PASSWORDS_CACHE: Optional[Set[str]] = None

def get_common_passwords() -> Set[str]:
    """
    Loads common passwords into a fast in-memory hash set.
    """
    global _COMMON_PASSWORDS_CACHE
    if _COMMON_PASSWORDS_CACHE is None:
        passwords = set()
        if os.path.exists(COMMON_PASSWORDS_FILE):
            try:
                with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        cleaned = line.strip().lower()
                        if cleaned and not cleaned.startswith("#"):
                            passwords.add(cleaned)
            except Exception:
                pass
        _COMMON_PASSWORDS_CACHE = passwords
    return _COMMON_PASSWORDS_CACHE

def analyze_length(password: str) -> Dict[str, Any]:
    """
    Analyzes password length and assigns educational classification band.
    """
    length = len(password)
    if length < 8:
        band = "Very Short (<8 chars)"
        status = "danger"
        explanation = "Extremely vulnerable to rapid offline brute-force attacks."
    elif 8 <= length <= 11:
        band = "Short (8-11 chars)"
        status = "warning"
        explanation = "Acceptable only if completely random; vulnerable if patterned."
    elif 12 <= length <= 15:
        band = "Good Length (12-15 chars)"
        status = "good"
        explanation = "Recommended baseline for everyday user accounts."
    else:
        band = "Strong Length (16+ chars)"
        status = "excellent"
        explanation = "Excellent search space depth against modern cracking rigs."
        
    return {
        "length": length,
        "band": band,
        "status": status,
        "explanation": explanation
    }

def analyze_characters(password: str) -> Dict[str, Any]:
    """
    Analyzes character composition, unique count, and diversity ratio.
    """
    length = len(password)
    if length == 0:
        return {
            "lowercase": 0,
            "uppercase": 0,
            "digits": 0,
            "symbols": 0,
            "spaces": 0,
            "unique_count": 0,
            "unique_character_ratio": 0.0,
            "character_types_present": 0
        }
        
    lower_cnt = sum(1 for c in password if c.islower())
    upper_cnt = sum(1 for c in password if c.isupper())
    digit_cnt = sum(1 for c in password if c.isdigit())
    space_cnt = sum(1 for c in password if c.isspace())
    symbol_cnt = sum(1 for c in password if c in string.punctuation)
    
    unique_chars = len(set(password))
    unique_ratio = round(unique_chars / length, 2)
    
    types_present = 0
    if lower_cnt > 0: types_present += 1
    if upper_cnt > 0: types_present += 1
    if digit_cnt > 0: types_present += 1
    if symbol_cnt > 0: types_present += 1
    
    return {
        "lowercase": lower_cnt,
        "uppercase": upper_cnt,
        "digits": digit_cnt,
        "symbols": symbol_cnt,
        "spaces": space_cnt,
        "unique_count": unique_chars,
        "unique_character_ratio": unique_ratio,
        "character_types_present": types_present
    }

def check_common_password(password: str) -> bool:
    """
    Checks if the password or its simplified lowercased version is on the common list.
    """
    if not password:
        return False
    common_set = get_common_passwords()
    pwd_lower = password.lower().strip()
    return (pwd_lower in common_set)

def analyze_password(
    password: str,
    context: Optional[Dict[str, str]] = None,
    policy_config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Primary defensive password analysis orchestrator.
    Input password is processed transiently in memory.
    """
    # 1. Structural Analyses
    length_metrics = analyze_length(password)
    char_metrics = analyze_characters(password)
    
    # 2. Common Password Detection
    is_common = check_common_password(password)
    
    # 3. Pattern & Weakness Detection
    findings = run_all_pattern_checks(password, context)
    if is_common:
        findings.insert(0, {
            "type": "common_password",
            "severity": "critical",
            "pattern": "matches known common password wordlist",
            "description": "Your password matches a commonly used password pattern and should not be used."
        })
        
    # 4. Entropy Estimation
    entropy_metrics = estimate_theoretical_entropy(password, pattern_count=len(findings))
    
    # 5. Strength Scoring Engine
    scoring_result = calculate_strength(
        length_metrics=length_metrics,
        char_metrics=char_metrics,
        pattern_findings=findings,
        is_common=is_common,
        entropy_metrics=entropy_metrics
    )
    
    # 6. Actionable Security Recommendations
    suggestions = generate_suggestions(
        score=scoring_result["score"],
        classification=scoring_result["classification"],
        findings=findings,
        length_metrics=length_metrics,
        char_metrics=char_metrics,
        is_common=is_common
    )
    
    # 7. Enterprise Policy Check (NIST SP 800-63B inspired)
    policy_result = check_password_policy(
        password=password,
        findings=findings,
        is_common=is_common,
        config=policy_config
    )
    
    return {
        "score": scoring_result["score"],
        "classification": scoring_result["classification"],
        "color": scoring_result["color"],
        "grade": scoring_result["grade"],
        "findings": findings,
        "suggestions": suggestions,
        "metrics": {
            "length": length_metrics,
            "characters": char_metrics,
            "entropy": entropy_metrics,
            "is_common": is_common,
            "score_breakdown": scoring_result["breakdown"],
            "policy": policy_result
        }
    }
