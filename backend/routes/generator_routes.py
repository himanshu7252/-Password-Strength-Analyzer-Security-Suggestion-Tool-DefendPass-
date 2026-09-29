"""
Password Generator API Routes
Provides endpoints for generating cryptographically secure passwords and passphrases.
"""
from flask import request, jsonify
from . import api_bp
from ..services.password_generator import generate_secure_password, generate_secure_passphrase

@api_bp.route('/generate-password', methods=['POST'])
def generate_password_endpoint():
    """
    POST /api/generate-password
    Generates a cryptographically strong random password using secrets module.
    """
    data = request.get_json(silent=True) or {}
    length = int(data.get("length", 16))
    use_upper = bool(data.get("use_upper", True))
    use_lower = bool(data.get("use_lower", True))
    use_digits = bool(data.get("use_digits", True))
    use_symbols = bool(data.get("use_symbols", True))
    
    result = generate_secure_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_symbols=use_symbols
    )
    return jsonify({"status": "success", "data": result}), 200

@api_bp.route('/generate-passphrase', methods=['POST'])
def generate_passphrase_endpoint():
    """
    POST /api/generate-passphrase
    Generates a memorable, high-entropy multi-word passphrase.
    """
    data = request.get_json(silent=True) or {}
    word_count = int(data.get("word_count", 4))
    separator = str(data.get("separator", "-"))[:3]
    capitalize = bool(data.get("capitalize", True))
    
    result = generate_secure_passphrase(
        word_count=word_count,
        separator=separator,
        capitalize=capitalize
    )
    return jsonify({"status": "success", "data": result}), 200
