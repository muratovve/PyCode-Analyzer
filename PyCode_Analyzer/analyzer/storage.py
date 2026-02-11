import sqlite3
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from .models import AnalysisReport, Finding

class SQLiteStorage:
    def __init__(self, db_path: str = "analysis.db"):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        """Initialize database schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Runs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    total_score INTEGER,
                    level TEXT,
                    error TEXT
                )
            """)

            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER,
                    category TEXT,
                    technique TEXT,
                    confidence TEXT,
                    score INTEGER,
                    location TEXT,
                    snippet TEXT,
                    description TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(id)
                )
            """)
            conn.commit()

    def save_run(self, report: AnalysisReport) -> int:
        """Save analysis report to DB and return run ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Insert run
            cursor.execute("""
                INSERT INTO runs (timestamp, file_path, total_score, level, error)
                VALUES (?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                report.file_path,
                report.total_score,
                report.obfuscation_level,
                report.error
            ))
            
            run_id = cursor.lastrowid
            
            # Insert findings
            if report.findings:
                findings_data = [
                    (
                        run_id,
                        f.category,
                        f.technique,
                        f.confidence,
                        f.score,
                        str(f.location),
                        f.snippet,
                        f.description
                    ) for f in report.findings
                ]
                
                cursor.executemany("""
                    INSERT INTO findings (run_id, category, technique, confidence, score, location, snippet, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, findings_data)
            
            conn.commit()
            return run_id

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent runs."""
        with self.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_run(self, run_id: int) -> Optional[Dict[str, Any]]:
        """Get full run details including findings."""
        with self.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Fetch run
            cursor.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
            run_row = cursor.fetchone()
            if not run_row:
                return None
            
            run_data = dict(run_row)
            
            # Fetch findings
            cursor.execute("SELECT * FROM findings WHERE run_id = ?", (run_id,))
            findings_rows = cursor.fetchall()
            run_data["findings"] = [dict(row) for row in findings_rows]
            
            return run_data
