"""
Analytics API Routes
Serves privacy-safe aggregate statistics for the dashboard.
"""
from flask import jsonify
from . import api_bp
from ..models.database import (
    get_aggregate_stats,
    get_weakness_frequency,
    get_score_distribution,
    get_length_distribution
)

@api_bp.route('/dashboard/stats', methods=['GET'])
def dashboard_stats_endpoint():
    """
    GET /api/dashboard/stats
    Returns aggregate stats (total analyses, average score, classification distribution).
    Zero credential or personal data is returned.
    """
    stats = get_aggregate_stats()
    return jsonify({"status": "success", "data": stats}), 200

@api_bp.route('/analytics/weaknesses', methods=['GET'])
def weaknesses_endpoint():
    """
    GET /api/analytics/weaknesses
    Returns frequency distribution of identified weakness categories.
    """
    weaknesses = get_weakness_frequency()
    return jsonify({"status": "success", "data": weaknesses}), 200

@api_bp.route('/analytics/score-distribution', methods=['GET'])
def score_distribution_endpoint():
    """
    GET /api/analytics/score-distribution
    Returns distribution of scores across 20-point buckets.
    """
    distribution = get_score_distribution()
    return jsonify({"status": "success", "data": distribution}), 200

@api_bp.route('/analytics/length-distribution', methods=['GET'])
def length_distribution_endpoint():
    """
    GET /api/analytics/length-distribution
    Returns count of analyzed passwords per length band.
    """
    distribution = get_length_distribution()
    return jsonify({"status": "success", "data": distribution}), 200
