"""
Scoring Engine Service
Calculates a nuanced 0-100 defensive strength score and maps it to
classifications: VERY WEAK, WEAK, MODERATE, STRONG, VERY STRONG.
Transparently tracks positive contributions and deductions.
"""
from typing import Dict, Any, List

def calculate_strength(
    length_metrics: Dict[str, Any],
    char_metrics: Dict[str, Any],
    pattern_findings: List[Dict[str, Any]],
    is_common: bool,
    entropy_metrics: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes an industry-oriented score based on length, unpredictability,
    diversity, pattern resistance, and common password absence.
    """
    score = 0
    breakdown = {
        "bonuses": [],
        "deductions": []
    }
    
    length = length_metrics.get("length", 0)
    
    # 1. Length Contribution (up to +35)
    if length == 0:
        length_points = 0
    elif length < 8:
        length_points = min(8, length * 1)
        breakdown["bonuses"].append({"factor": "Short Length", "points": length_points})
    elif 8 <= length <= 11:
        length_points = 12 + (length - 8) * 2  # 12 to 18
        breakdown["bonuses"].append({"factor": "Moderate Length (8-11)", "points": length_points})
    elif 12 <= length <= 15:
        length_points = 22 + (length - 12) * 2  # 22 to 28
        breakdown["bonuses"].append({"factor": "Good Length (12-15)", "points": length_points})
    else:  # 16+
        length_points = 35
        breakdown["bonuses"].append({"factor": "Strong Length (16+)", "points": 35})
        
    score += length_points
    
    # 2. Character Diversity Contribution (up to +15)
    types_count = char_metrics.get("character_types_present", 0)
    diversity_table = {0: 0, 1: 3, 2: 7, 3: 11, 4: 15}
    diversity_points = diversity_table.get(types_count, 15)
    if diversity_points > 0:
        breakdown["bonuses"].append({
            "factor": f"Character Diversity ({types_count}/4 classes)",
            "points": diversity_points
        })
    score += diversity_points
    
    # 3. Unique Character Ratio Contribution (up to +10)
    unique_ratio = char_metrics.get("unique_character_ratio", 0.0)
    unique_points = round(unique_ratio * 10)
    if unique_points > 0:
        breakdown["bonuses"].append({
            "factor": "Character Variety / Uniqueness",
            "points": unique_points
        })
    score += unique_points
    
    # 4. Pattern Resistance Bonus (up to +20)
    pattern_count = len(pattern_findings)
    if pattern_count == 0 and length >= 8:
        score += 20
        breakdown["bonuses"].append({"factor": "High Pattern Resistance (Zero detected walks/repeats)", "points": 20})
    elif pattern_count == 1:
        score += 8
        breakdown["bonuses"].append({"factor": "Partial Pattern Resistance", "points": 8})
        
    # 5. Non-Common Password Bonus (up to +10)
    if not is_common and length > 0:
        score += 10
        breakdown["bonuses"].append({"factor": "Not in Common Password Corpus", "points": 10})
        
    # 6. Effective Entropy / Unpredictability (up to +10)
    eff_bits = entropy_metrics.get("effective_bits", 0.0)
    if eff_bits >= 70:
        score += 10
        breakdown["bonuses"].append({"factor": "High Effective Entropy (>70 bits)", "points": 10})
    elif eff_bits >= 45:
        score += 6
        breakdown["bonuses"].append({"factor": "Moderate Effective Entropy (45-70 bits)", "points": 6})
    elif eff_bits >= 25:
        score += 2
        breakdown["bonuses"].append({"factor": "Low Effective Entropy", "points": 2})

    # === PENALTIES ===
    # A. Detected Patterns Deductions
    for finding in pattern_findings:
        f_type = finding.get("type")
        if f_type == "keyboard_pattern":
            score -= 15
            breakdown["deductions"].append({"factor": "Keyboard Walk Pattern", "penalty": 15})
        elif f_type in ("numeric_sequence", "alphabetical_sequence"):
            score -= 12
            breakdown["deductions"].append({"factor": "Sequential Characters", "penalty": 12})
        elif f_type in ("repeated_characters", "repeated_substring"):
            score -= 12
            breakdown["deductions"].append({"factor": "Repetitive Characters/Block", "penalty": 12})
        elif f_type == "predictable_formula":
            score -= 15
            breakdown["deductions"].append({"factor": "Common Predictable Template (Word+Num+Symbol)", "penalty": 15})
        elif f_type == "predictable_year":
            score -= 10
            breakdown["deductions"].append({"factor": "Predictable Year Included", "penalty": 10})
        elif f_type == "personal_information":
            score -= 25
            breakdown["deductions"].append({"factor": "Contextual Personal Information Overlap", "penalty": 25})
            
    # B. Common Password Severe Override
    if is_common:
        score -= 40
        breakdown["deductions"].append({"factor": "Known Common Password List Match", "penalty": 40})
        # If it's a known common password, cap the maximum score at 15
        score = min(score, 15)

    # Clean bounds [0, 100]
    final_score = max(0, min(100, score))
    
    # Critical security calibration: Passwords shorter than 8 characters are trivially
    # brute-forced within seconds in modern attacker models, regardless of diversity.
    if length < 6:
        final_score = min(final_score, 12)
    elif length < 8:
        final_score = min(final_score, 20)
        
    # Empty input safeguard
    if length == 0:
        final_score = 0

    # Classification Mapping
    if final_score <= 20:
        classification = "VERY WEAK"
        color = "#ef4444"  # Red
        grade = "F"
    elif final_score <= 40:
        classification = "WEAK"
        color = "#f97316"  # Orange
        grade = "D"
    elif final_score <= 60:
        classification = "MODERATE"
        color = "#eab308"  # Yellow
        grade = "C"
    elif final_score <= 80:
        classification = "STRONG"
        color = "#10b981"  # Light Green
        grade = "B"
    else:
        classification = "VERY STRONG"
        color = "#059669"  # Emerald
        grade = "A"

    return {
        "score": final_score,
        "classification": classification,
        "color": color,
        "grade": grade,
        "breakdown": breakdown
    }
