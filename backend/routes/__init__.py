"""
Flask Blueprints routes initialization
"""
from flask import Blueprint

api_bp = Blueprint('api', __name__, url_prefix='/api')

from . import analyzer_routes
from . import generator_routes
from . import analytics_routes
from . import policy_routes

__all__ = ['api_bp']
