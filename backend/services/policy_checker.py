"""
Password Policy Checker Service
Evaluates passwords against modern enterprise policies (NIST SP 800-63B inspired)
and highlights the critical distinction between Policy Compliance and True Cryptographic Strength.
"""
from typing import Dict, Any, List, Optional
import string

DEFAULT_POLICY = {
    "min_length": 12,
    "max_length": 128,
    "require_min_classes": 3,  # out of 4: upper, lower, digit, symbol
    "disallow_common": True,
    "disallow_personal_info": True,
    "disallow_keyboard_walks": True,
    "allow_spaces": True
}

def check_password_policy(
    password: str,
    findings: List[Dict[str, Any]],
    is_common: bool,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates password against a configurable enterprise security policy.
    """
    policy = {**DEFAULT_POLICY, **(config or {})}
    length = len(password)
    
    rules = []
    
    # 1. Minimum Length Rule
    min_len = policy.get("min_length", 12)
    has_min_len = length >= min_len
    rules.append({
        "rule": f"Minimum length of {min_len} characters",
        "passed": has_min_len,
        "detail": f"Current length is {length} characters."
    })
    
    # 2. Maximum Length Rule (NIST recommends at least 64-128 chars allowed)
    max_len = policy.get("max_length", 128)
    has_max_len = length <= max_len
    rules.append({
        "rule": f"Maximum length threshold ({max_len} characters)",
        "passed": has_max_len,
        "detail": f"Current length: {length}."
    })
    
    # 3. Common Password Screening (NIST SP 800-63B mandate)
    if policy.get("disallow_common", True):
        rules.append({
            "rule": "Must not appear on common/breached password blocklists",
            "passed": not is_common,
            "detail": "Password is known and commonly used." if is_common else "Passed blocklist check."
        })
        
    # 4. Character Class Variety
    req_classes = policy.get("require_min_classes", 3)
    present_classes = 0
    if any(c.islower() for c in password):
        present_classes += 1
    if any(c.isupper() for c in password):
        present_classes += 1
    if any(c.isdigit() for c in password):
        present_classes += 1
    if any(c in string.punctuation for c in password):
        present_classes += 1
        
    has_classes = present_classes >= req_classes
    rules.append({
        "rule": f"Must contain at least {req_classes} of 4 character categories (Upper, Lower, Digit, Symbol)",
        "passed": has_classes,
        "detail": f"Contains {present_classes} category(ies)."
    })
    
    # 5. Personal Context Screening
    if policy.get("disallow_personal_info", True):
        has_pii = any(f.get("type") == "personal_information" for f in findings)
        rules.append({
            "rule": "Must not contain personal identifying information",
            "passed": not has_pii,
            "detail": "Contains personal context elements." if has_pii else "No personal context detected."
        })
        
    # 6. Keyboard Walks
    if policy.get("disallow_keyboard_walks", True):
        has_kb = any(f.get("type") == "keyboard_pattern" for f in findings)
        rules.append({
            "rule": "Must not contain standard keyboard walks (e.g. QWERTY)",
            "passed": not has_kb,
            "detail": "Keyboard sequence detected." if has_kb else "No keyboard walk detected."
        })
        
    policy_passed = all(r["passed"] for r in rules)
    
    educational_note = (
        "COMPLIANCE vs STRENGTH: A password may comply with standard enterprise policies "
        "(e.g., 'Password123!') while remaining computationally predictable. Conversely, "
        "a 20-character random lowercase passphrase may fail legacy composition rules despite "
        "providing superior entropy. Modern guidelines (NIST SP 800-63B) favor length and "
        "breach-screening over arbitrary character composition rules."
    )
    
    return {
        "policy_passed": policy_passed,
        "rules": rules,
        "educational_note": educational_note
    }
