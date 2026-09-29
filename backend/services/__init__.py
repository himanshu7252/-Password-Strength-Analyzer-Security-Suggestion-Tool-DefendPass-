"""
Password Strength Analyzer & Security Suggestion Tool
Services Module
"""
from .password_analyzer import analyze_password
from .pattern_detector import run_all_pattern_checks
from .entropy_estimator import estimate_theoretical_entropy
from .scoring_engine import calculate_strength
from .suggestion_engine import generate_suggestions
from .password_generator import generate_secure_password, generate_secure_passphrase
from .policy_checker import check_password_policy

__all__ = [
    "analyze_password",
    "run_all_pattern_checks",
    "estimate_theoretical_entropy",
    "calculate_strength",
    "generate_suggestions",
    "generate_secure_password",
    "generate_secure_passphrase",
    "check_password_policy",
]
