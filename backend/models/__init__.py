"""
Database and models initialization
"""
from .database import (
    init_db,
    record_analysis_metadata,
    get_aggregate_stats,
    get_weakness_frequency,
    get_score_distribution,
    get_length_distribution,
    seed_demo_analytics_if_empty
)

__all__ = [
    "init_db",
    "record_analysis_metadata",
    "get_aggregate_stats",
    "get_weakness_frequency",
    "get_score_distribution",
    "get_length_distribution",
    "seed_demo_analytics_if_empty"
]
