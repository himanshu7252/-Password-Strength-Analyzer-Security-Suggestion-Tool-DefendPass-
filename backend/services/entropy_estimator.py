"""
Entropy Estimator Service
Calculates theoretical entropy (L * log2(N)) and contextual/effective entropy,
clearly detailing educational limitations and real-world attacker models.
"""
import math
import string
from typing import Dict, Any, List

def estimate_theoretical_entropy(password: str, pattern_count: int = 0) -> Dict[str, Any]:
    """
    Calculates theoretical entropy based on character pool size and length,
    plus an adjusted 'effective' entropy score that accounts for predictability.
    
    Formula: E = L * log2(N)
    L = Length of password
    N = Total character pool size based on character categories used
    """
    if not password:
        return {
            "theoretical_bits": 0.0,
            "effective_bits": 0.0,
            "pool_size": 0,
            "character_classes": [],
            "entropy_rating": "Zero",
            "educational_note": "Empty password provides zero entropy."
        }
        
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(c in string.punctuation for c in password)
    has_spaces = any(c.isspace() for c in password)
    has_unicode = any(ord(c) > 127 for c in password)
    
    pool_size = 0
    classes = []
    
    if has_lower:
        pool_size += 26
        classes.append("Lowercase (26)")
    if has_upper:
        pool_size += 26
        classes.append("Uppercase (26)")
    if has_digits:
        pool_size += 10
        classes.append("Digits (10)")
    if has_symbols:
        pool_size += 32
        classes.append("Symbols (32)")
    if has_spaces:
        pool_size += 1
        classes.append("Spaces (1)")
    if has_unicode:
        pool_size += 30
        classes.append("Extended Unicode")
        
    # Safeguard against 0 or 1 pool size
    if pool_size <= 1:
        theoretical_bits = float(length)
    else:
        theoretical_bits = length * math.log2(pool_size)
        
    # Effective entropy adjusts for patterns and repetition
    # Patterns (e.g. sequences, keyboard walks, dictionary words) drastically reduce brute-force space
    penalty_ratio = max(0.2, 1.0 - (pattern_count * 0.18))
    effective_bits = theoretical_bits * penalty_ratio
    
    if effective_bits < 28:
        entropy_rating = "Very Low"
    elif effective_bits < 45:
        entropy_rating = "Low"
    elif effective_bits < 65:
        entropy_rating = "Moderate"
    elif effective_bits < 85:
        entropy_rating = "High"
    else:
        entropy_rating = "Very High"
        
    educational_note = (
        "Theoretical entropy assumes characters are chosen uniformly at random. "
        "Because human-crafted passwords follow dictionary words, common substitutions, "
        "and keyboard layouts, raw theoretical entropy usually OVERESTIMATES actual security. "
        "Effective entropy factors in structural predictability."
    )
    
    return {
        "theoretical_bits": round(theoretical_bits, 1),
        "effective_bits": round(effective_bits, 1),
        "pool_size": pool_size,
        "character_classes": classes,
        "entropy_rating": entropy_rating,
        "educational_note": educational_note
    }
