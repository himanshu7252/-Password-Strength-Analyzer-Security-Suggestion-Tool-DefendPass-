"""
Password Strength Analyzer & Security Suggestion Tool
Main Flask Application Server

DEFENSIVE CYBERSECURITY DESIGN:
1. Local execution & In-memory processing: Passwords are never sent to third-party APIs.
2. Zero Password Logging: HTTP request bodies are never echoed or dumped to logs.
3. Zero Password Persistence: No database column exists for passwords or hashes.
4. Serves frontend directly at http://127.0.0.1:5000 and supports CORS for decoupled setups.
"""
import os
import sys
import logging
from flask import Flask, send_from_directory, render_template
from flask_cors import CORS

from .routes import api_bp
from .models.database import init_db, seed_demo_analytics_if_empty

# Determine frontend directory
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

def create_app():
    """Application factory for Flask backend."""
    app = Flask(
        __name__,
        static_folder=FRONTEND_DIR,
        static_url_path=""
    )
    
    # Enable CORS for local cross-origin development
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Register API blueprint
    app.register_blueprint(api_bp)
    
    # Initialize SQLite schema and seed safe demo analytics
    with app.app_context():
        init_db()
        seed_demo_analytics_if_empty()
        
    # Serve Frontend UI
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:filename>")
    def serve_static(filename):
        return send_from_directory(FRONTEND_DIR, filename)

    # Privacy filter: suppress request body logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    return app

if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("FLASK_PORT", 5000))
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    print("=" * 80)
    print(" [DEFENDPASS] PASSWORD STRENGTH ANALYZER & SECURITY SUGGESTION TOOL (DEFENSIVE) ")
    print("=" * 80)
    print(f" -> Server running locally at: http://{host}:{port}/")
    print(" -> Privacy Guarantee: No passwords or hashes are logged or stored.")
    print(" -> Defensive Mode: Active (Local in-memory evaluation only)")
    print("=" * 80)
    app.run(host=host, port=port, debug=False)
