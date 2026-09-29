"""
Policy Checker API Routes
Provides endpoints for enterprise policy verification and schema retrieval.
"""
from flask import request, jsonify
from . import api_bp
from ..services.policy_checker import check_password_policy, DEFAULT_POLICY
from ..services.pattern_detector import run_all_pattern_checks
from ..services.password_analyzer import check_common_password

@api_bp.route('/policy/default', methods=['GET'])
def get_default_policy():
    """
    GET /api/policy/default
    Returns the standard NIST SP 800-63B inspired policy configuration.
    """
    return jsonify({"status": "success", "data": DEFAULT_POLICY}), 200

@api_bp.route('/check-policy', methods=['POST'])
def check_policy_endpoint():
    """
    POST /api/check-policy
    Evaluates password specifically against compliance policy rules.
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    policy_config = data.get("policy", DEFAULT_POLICY)
    
    findings = run_all_pattern_checks(password)
    is_common = check_common_password(password)
    
    result = check_password_policy(
        password=password,
        findings=findings,
        is_common=is_common,
        config=policy_config
    )
    return jsonify({"status": "success", "data": result}), 200
