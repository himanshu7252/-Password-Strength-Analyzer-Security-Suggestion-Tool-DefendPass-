"""
Suggestion Engine Service
Generates targeted, actionable defensive recommendations and password hygiene advice.
CRITICAL DEFENSIVE RULE: Never echo the user's password in suggestions or feedback.
"""
from typing import Dict, Any, List

def generate_suggestions(
    score: int,
    classification: str,
    findings: List[Dict[str, Any]],
    length_metrics: Dict[str, Any],
    char_metrics: Dict[str, Any],
    is_common: bool
) -> Dict[str, Any]:
    """
    Builds personalized, specific recommendations to remediate identified weaknesses.
    """
    immediate_actions = []
    hygiene_recommendations = []
    passphrase_tip = ""
    
    length = length_metrics.get("length", 0)
    
    # 1. Common Password Finding
    if is_common:
        immediate_actions.append(
            "Replace this password immediately. It matches known dictionary/breach wordlists "
            "and will be cracked within seconds by standard wordlist attacks."
        )
        
    # 2. Length-based suggestions
    if length < 8:
        immediate_actions.append(
            "Significantly increase length. Passwords shorter than 8 characters can be "
            "exhaustively brute-forced in minutes regardless of character composition."
        )
    elif length < 12:
        immediate_actions.append(
            "Aim for at least 12 to 16 characters. Each additional character exponentially "
            "expands the search space against offline brute-force attempts."
        )
        
    # 3. Pattern-based suggestions
    for finding in findings:
        f_type = finding.get("type")
        if f_type in ("numeric_sequence", "alphabetical_sequence"):
            immediate_actions.append(
                "Remove ascending or descending sequences (such as '1234' or 'abcd'). "
                "Attackers use automated mask attacks that specifically prioritize consecutive sequences."
            )
        elif f_type == "keyboard_pattern":
            immediate_actions.append(
                "Avoid keyboard walks (such as 'qwerty' or 'asdf'). Keyboard paths are "
                "among the very first heuristics tested by password audit tools."
            )
        elif f_type in ("repeated_characters", "repeated_substring"):
            immediate_actions.append(
                "Eliminate repeating characters and patterned syllables. Repetition drastically "
                "collapses effective keyspace entropy."
            )
        elif f_type == "predictable_year":
            immediate_actions.append(
                "Avoid four-digit years or dates. Rule-based cracking engines append years "
                "(e.g., 2020-2026) to almost all base dictionary words."
            )
        elif f_type == "predictable_formula":
            immediate_actions.append(
                "Avoid standard composition formulas (Capital letter + word + digits + symbol). "
                "While this satisfies legacy complexity rules, it remains highly predictable."
            )
        elif f_type == "personal_information":
            immediate_actions.append(
                "Remove personal identifying details (names, birth years, institution names). "
                "Targeted spear-phishing and social engineering wordlists prioritize personal data."
            )
            
    # De-duplicate immediate actions
    immediate_actions = list(dict.fromkeys(immediate_actions))
    
    # 4. Passphrase Education Tip
    if length < 15 or classification in ("VERY WEAK", "WEAK", "MODERATE"):
        passphrase_tip = (
            "Consider switching to a 4-to-5 random word passphrase (e.g., 'cactus-cobalt-orbit-lantern'). "
            "Passphrases provide high mathematical entropy while remaining much easier to memorize than random strings."
        )
        
    # 5. Universal Security Hygiene Recommendations
    hygiene_recommendations.append("Use a dedicated Password Manager to generate and store unique, high-entropy credentials.")
    hygiene_recommendations.append("Never reuse credentials across multiple services to prevent Credential Stuffing attacks.")
    hygiene_recommendations.append("Enable Multi-Factor Authentication (MFA / 2FA) using an Authenticator app or hardware FIDO2 key.")
    hygiene_recommendations.append("Verify URLs before entering credentials to protect against modern adversary-in-the-middle (AiTM) phishing.")

    return {
        "immediate_actions": immediate_actions,
        "passphrase_tip": passphrase_tip,
        "hygiene_recommendations": hygiene_recommendations
    }
