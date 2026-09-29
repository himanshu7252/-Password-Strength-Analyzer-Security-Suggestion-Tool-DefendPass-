"""
Database & Analytics Model
Manages privacy-preserving aggregate metrics using SQLite.

PRIVACY-BY-DESIGN DEFENSIVE MANDATE:
- NEVER creates a 'password' column.
- NEVER stores plaintext, encrypted, or hashed passwords.
- Records ONLY anonymous aggregate telemetry (score, classification, length, weakness types).
- Fulfills GDPR Data Minimization (Article 5(1)(c)) and ISO 27001 principles.
"""
import sqlite3
import os
from typing import Dict, Any, List, Optional
from datetime import datetime

DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "analytics.db")
)

def get_connection():
    """Returns a connection to the SQLite analytics database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database schema with zero password storage capability.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Table 1: Safe aggregate metadata only
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                password_length INTEGER NOT NULL,
                unique_character_ratio REAL NOT NULL,
                weakness_count INTEGER NOT NULL,
                entropy_estimate REAL NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table 2: Identified weakness categories (no user data)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
            )
        """)
        
        conn.commit()

def record_analysis_metadata(
    score: int,
    classification: str,
    password_length: int,
    unique_character_ratio: float,
    weakness_count: int,
    entropy_estimate: float,
    findings: List[Dict[str, Any]]
) -> int:
    """
    Persists ONLY safe aggregate metadata. Rejects any attempt to store passwords.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analyses (
                score, classification, password_length,
                unique_character_ratio, weakness_count, entropy_estimate
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            score, classification, password_length,
            unique_character_ratio, weakness_count, entropy_estimate
        ))
        
        analysis_id = cursor.lastrowid
        
        for f in findings:
            cursor.execute("""
                INSERT INTO findings (analysis_id, finding_type, severity, description)
                VALUES (?, ?, ?, ?)
            """, (
                analysis_id,
                f.get("type", "unknown"),
                f.get("severity", "low"),
                f.get("description", "")
            ))
            
        conn.commit()
        return analysis_id

def get_aggregate_stats() -> Dict[str, Any]:
    """
    Calculates summary metrics across all historical analyses.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Overall counts
        cursor.execute("""
            SELECT 
                COUNT(*) as total_analyses,
                AVG(score) as avg_score,
                AVG(password_length) as avg_length,
                AVG(entropy_estimate) as avg_entropy
            FROM analyses
        """)
        summary_row = cursor.fetchone()
        
        total = summary_row["total_analyses"] or 0
        avg_score = round(summary_row["avg_score"] or 0.0, 1)
        avg_length = round(summary_row["avg_length"] or 0.0, 1)
        avg_entropy = round(summary_row["avg_entropy"] or 0.0, 1)
        
        # Classification counts
        cursor.execute("""
            SELECT classification, COUNT(*) as count
            FROM analyses
            GROUP BY classification
        """)
        class_rows = cursor.fetchall()
        
        distribution = {
            "VERY WEAK": 0,
            "WEAK": 0,
            "MODERATE": 0,
            "STRONG": 0,
            "VERY STRONG": 0
        }
        for r in class_rows:
            distribution[r["classification"]] = r["count"]
            
        return {
            "total_analyses": total,
            "average_score": avg_score,
            "average_length": avg_length,
            "average_entropy": avg_entropy,
            "classification_distribution": distribution
        }

def get_weakness_frequency() -> List[Dict[str, Any]]:
    """
    Returns the frequency of each pattern weakness identified.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT finding_type, COUNT(*) as frequency
            FROM findings
            GROUP BY finding_type
            ORDER BY frequency DESC
            LIMIT 10
        """)
        rows = cursor.fetchall()
        return [{"type": r["finding_type"], "frequency": r["frequency"]} for r in rows]

def get_score_distribution() -> List[Dict[str, Any]]:
    """
    Returns distribution of scores grouped in 20-point bins.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                CASE
                    WHEN score BETWEEN 0 AND 20 THEN '0-20'
                    WHEN score BETWEEN 21 AND 40 THEN '21-40'
                    WHEN score BETWEEN 41 AND 60 THEN '41-60'
                    WHEN score BETWEEN 61 AND 80 THEN '61-80'
                    ELSE '81-100'
                END as bucket,
                COUNT(*) as count
            FROM analyses
            GROUP BY bucket
            ORDER BY bucket ASC
        """)
        rows = cursor.fetchall()
        return [{"bucket": r["bucket"], "count": r["count"]} for r in rows]

def get_length_distribution() -> List[Dict[str, Any]]:
    """
    Returns distribution of password lengths grouped in educational bands.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                CASE
                    WHEN password_length < 8 THEN '< 8 chars'
                    WHEN password_length BETWEEN 8 AND 11 THEN '8 - 11 chars'
                    WHEN password_length BETWEEN 12 AND 15 THEN '12 - 15 chars'
                    ELSE '16+ chars'
                END as length_band,
                COUNT(*) as count
            FROM analyses
            GROUP BY length_band
        """)
        rows = cursor.fetchall()
        return [{"band": r["length_band"], "count": r["count"]} for r in rows]

def seed_demo_analytics_if_empty():
    """
    Seeds a small set of synthetic educational metadata if the database is brand new.
    Provides immediate visual feedback in the dashboard without requiring real user runs.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM analyses")
        if cursor.fetchone()["count"] == 0:
            # Synthetic demonstration telemetry batches
            samples = [
                (10, "VERY WEAK", 6, 0.5, 3, 15.5, [("common_password", "critical", "Common password"), ("numeric_sequence", "medium", "Ascending numbers")]),
                (15, "VERY WEAK", 7, 0.4, 2, 21.0, [("keyboard_pattern", "high", "QWERTY walk")]),
                (35, "WEAK", 12, 0.8, 2, 42.0, [("predictable_formula", "high", "Word+digits+symbol"), ("numeric_sequence", "medium", "123 suffix")]),
                (45, "MODERATE", 10, 0.9, 1, 55.0, [("predictable_year", "medium", "Contained 2024")]),
                (55, "MODERATE", 11, 0.85, 1, 62.0, [("repeated_characters", "medium", "Repeated letters")]),
                (75, "STRONG", 14, 0.92, 0, 78.0, []),
                (80, "STRONG", 16, 0.94, 0, 85.0, []),
                (95, "VERY STRONG", 20, 0.95, 0, 110.0, []),
                (98, "VERY STRONG", 24, 0.96, 0, 135.0, []),
            ]
            for s in samples:
                cursor.execute("""
                    INSERT INTO analyses (
                        score, classification, password_length,
                        unique_character_ratio, weakness_count, entropy_estimate
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (s[0], s[1], s[2], s[3], s[4], s[5]))
                a_id = cursor.lastrowid
                for f in s[6]:
                    cursor.execute("""
                        INSERT INTO findings (analysis_id, finding_type, severity, description)
                        VALUES (?, ?, ?, ?)
                    """, (a_id, f[0], f[1], f[2]))
            conn.commit()
