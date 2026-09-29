"""
Analyzer API Routes
Handles transient password analysis requests with zero persistence of user passwords.
"""
from flask import request, jsonify
from . import api_bp
from ..services.password_analyzer import analyze_password
from ..models.database import record_analysis_metadata

@api_bp.route('/analyze', methods=['POST'])
def analyze_endpoint():
    """
    POST /api/analyze
    Analyzes submitted password transiently in memory.
    NEVER logs or persists the submitted password string.
    Only writes anonymous aggregate telemetry (score, classification, length).
    """
    if not request.is_json:
        return jsonify({
            "status": "error",
            "message": "Content-Type must be application/json"
        }), 400
        
    data = request.get_json(silent=True) or {}
    password = data.get("password")
    
    # Validation
    if password is None or not isinstance(password, str):
        return jsonify({
            "status": "error",
            "message": "Missing or invalid 'password' field in JSON body"
        }), 400
        
    if len(password) > 512:
        return jsonify({
            "status": "error",
            "message": "Password exceeds maximum allowed evaluation threshold (512 characters)"
        }), 400
        
    context = data.get("context")
    policy_config = data.get("policy")
    save_analytics = data.get("save_analytics", True)
    
    # Perform in-memory analysis
    result = analyze_password(password, context=context, policy_config=policy_config)
    
    # Record strictly safe aggregate metrics if requested and not empty
    if save_analytics and len(password) > 0:
        try:
            record_analysis_metadata(
                score=result["score"],
                classification=result["classification"],
                password_length=result["metrics"]["length"]["length"],
                unique_character_ratio=result["metrics"]["characters"]["unique_character_ratio"],
                weakness_count=len(result["findings"]),
                entropy_estimate=result["metrics"]["entropy"]["effective_bits"],
                findings=result["findings"]
            )
        except Exception:
            # Analytics recording failure must never break the analysis response
            pass
            
    return jsonify({
        "status": "success",
        "score": result["score"],
        "classification": result["classification"],
        "color": result["color"],
        "grade": result["grade"],
        "findings": result["findings"],
        "suggestions": result["suggestions"],
        "metrics": result["metrics"]
    }), 200
