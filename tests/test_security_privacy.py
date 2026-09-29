"""
Automated Security, Privacy, and Defensive Compliance Test Suite
Verifies:
1. Zero plaintext password storage (Database schema inspection)
2. Zero password hash storage (No unnecessary hash persistence)
3. Zero credential leakage in API responses or recommendations
4. Input sanitization & safe transient handling
5. Privacy-preserving aggregate analytics integrity
"""
import sqlite3
import pytest
from backend.app import create_app
from backend.models.database import (
    get_connection,
    record_analysis_metadata,
    get_aggregate_stats,
    DB_PATH
)
from backend.services.password_analyzer import analyze_password

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Test 28: Verify database schema contains ZERO password columns
def test_28_database_has_no_password_columns():
    """
    CRITICAL DEFENSIVE TEST:
    Inspects sqlite master table columns for 'analyses' and 'findings'.
    Asserts no 'password', 'plaintext', 'pwd', or 'hash' columns exist.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Check analyses table
        cursor.execute("PRAGMA table_info(analyses)")
        analyses_cols = [row["name"].lower() for row in cursor.fetchall()]
        
        # Check findings table
        cursor.execute("PRAGMA table_info(findings)")
        findings_cols = [row["name"].lower() for row in cursor.fetchall()]
        
        forbidden_columns = {
            "password", "plaintext", "pwd", "hash", "secret", "credential",
            "user_password", "raw_password", "password_hash", "hashed_password"
        }
        
        for col in analyses_cols:
            assert col not in forbidden_columns, f"Forbidden column '{col}' detected in analyses schema!"
            # Also ensure no column is storing actual passwords
            assert not col.startswith("raw_") and not col.endswith("_hash")
                
        for col in findings_cols:
            assert col not in forbidden_columns, f"Forbidden column '{col}' detected in findings schema!"

# Test 29: Verify password is never echoed in suggestions or descriptions
def test_29_password_never_echoed_in_suggestions():
    """
    Verifies that the exact submitted password is never reflected in findings or recommendations.
    """
    synthetic_secret = "ConfidentialStr!987654"
    result = analyze_password(synthetic_secret)
    
    # Check all suggestion strings
    for action in result["suggestions"]["immediate_actions"]:
        assert synthetic_secret not in action
        
    for hygiene in result["suggestions"]["hygiene_recommendations"]:
        assert synthetic_secret not in hygiene
        
    if result["suggestions"]["passphrase_tip"]:
        assert synthetic_secret not in result["suggestions"]["passphrase_tip"]
        
    # Check all finding descriptions
    for finding in result["findings"]:
        assert synthetic_secret not in finding["description"]

# Test 30: Verify analytics table stores strictly anonymous metadata
def test_30_analytics_storage_integrity():
    """
    Verifies that record_analysis_metadata persists only numerical/categorical telemetry.
    """
    a_id = record_analysis_metadata(
        score=78,
        classification="STRONG",
        password_length=16,
        unique_character_ratio=0.9,
        weakness_count=1,
        entropy_estimate=82.5,
        findings=[{"type": "numeric_sequence", "severity": "medium", "description": "Sequential test"}]
    )
    assert a_id is not None
    
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (a_id,))
        row = cursor.fetchone()
        assert row["score"] == 78
        assert row["classification"] == "STRONG"
        assert row["password_length"] == 16

# Test 31: POST /api/analyze handles valid requests without leaking password
def test_31_api_analyze_safe_response(client):
    secret_payload = "TargetDemoPassword123!"
    res = client.post('/api/analyze', json={"password": secret_payload})
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "score" in data
    assert "classification" in data
    # Password itself must not be echoed back as a top-level key
    assert "password" not in data

# Test 32: POST /api/analyze input validation
def test_32_api_analyze_validation(client):
    # Non-string input
    res1 = client.post('/api/analyze', json={"password": 12345})
    assert res1.status_code == 400
    
    # Missing body
    res2 = client.post('/api/analyze', data="not json", content_type="text/plain")
    assert res2.status_code == 400

# Test 33: GET /api/dashboard/stats returns only aggregate statistics
def test_33_api_dashboard_stats_privacy(client):
    res = client.get('/api/dashboard/stats')
    assert res.status_code == 200
    data = res.get_json()
    assert "data" in data
    stats = data["data"]
    assert "total_analyses" in stats
    assert "average_score" in stats
    assert "classification_distribution" in stats
    # Zero user or password data
    assert "passwords" not in stats
    assert "users" not in stats
