"""
Database management module for PhishGuard.
Uses SQLite for local storage with parameterized queries for security.
"""

import os
import sqlite3
from typing import Optional

# Path to the SQLite database file
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishguard.db')


def get_db_connection() -> sqlite3.Connection:
    """Create and return an SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Initialize the SQLite database schema if tables do not exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Index on email for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
        """)
        # Scan history table (stores user URL scans)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at)
        """)
        conn.commit()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    """Retrieve a user by email using case-insensitive comparison."""
    if not email:
        return None
    normalized_email = email.strip().lower()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, email, password_hash, created_at FROM users WHERE email = ? COLLATE NOCASE",
            (normalized_email,)
        )
        return cursor.fetchone()


def create_user(name: str, email: str, password_hash: str) -> int:
    """
    Insert a new user record into the database.
    
    Parameters:
        name: Full name of the user
        email: User's email address
        password_hash: Securely hashed password (never plain-text)
        
    Returns:
        The newly inserted user's ID
        
    Raises:
        sqlite3.IntegrityError: If the email already exists
        sqlite3.Error: For any other database error
    """
    normalized_name = name.strip()
    normalized_email = email.strip().lower()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (normalized_name, normalized_email, password_hash)
        )
        conn.commit()
        return cursor.lastrowid


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    """Retrieve a user by their unique primary key ID."""
    if not user_id:
        return None
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, email, password_hash, created_at FROM users WHERE id = ?",
            (user_id,)
        )
        return cursor.fetchone()


def get_user_scan_stats(user_id: int) -> dict:
    """
    Calculate scan statistics for a specific authenticated user.
    Always filters by user_id to ensure user data isolation.
    Returns zeroed statistics if the scan_history table does not exist or user has no scans.
    """
    default_stats = {
        'total_scans': 0,
        'phishing_detected': 0,
        'legitimate_urls': 0
    }
    if not user_id:
        return default_stats

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Safe check if scan_history exists in SQLite
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'"
        )
        if not cursor.fetchone():
            return default_stats

        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN LOWER(prediction) = 'phishing' THEN 1 ELSE 0 END) as phishing_detected,
                SUM(CASE WHEN LOWER(prediction) = 'legitimate' THEN 1 ELSE 0 END) as legitimate_urls
            FROM scan_history
            WHERE user_id = ?
        """, (user_id,))
        row = cursor.fetchone()
        if row:
            return {
                'total_scans': row['total_scans'] or 0,
                'phishing_detected': row['phishing_detected'] or 0,
                'legitimate_urls': row['legitimate_urls'] or 0
            }
        return default_stats


def get_user_recent_scans(user_id: int, limit: int = 5) -> list:
    """
    Retrieve the most recent scans for a specific authenticated user.
    Always filters by user_id to ensure strict privacy and data isolation.
    Returns an empty list if scan_history does not exist or has no records.
    """
    if not user_id:
        return []

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Safe check if scan_history exists in SQLite
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_history'"
        )
        if not cursor.fetchone():
            return []

        cursor.execute("""
            SELECT id, user_id, url, prediction, confidence, scanned_at
            FROM scan_history
            WHERE user_id = ?
            ORDER BY scanned_at DESC, id DESC
            LIMIT ?
        """, (user_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def create_scan_record(user_id: int, url: str, prediction: str, confidence: float) -> int:
    """
    Persist an authenticated user's URL scan verdict to the scan_history table.
    Guarantees idempotency against rapid duplicate submissions (e.g. multi-clicks or race conditions).
    
    Parameters:
        user_id: Primary key of the authenticated user
        url: The evaluated URL string
        prediction: 'Phishing' or 'Legitimate'
        confidence: Float probability score (e.g. 0.985)
        
    Returns:
        The primary key ID of the newly inserted or existing record.
    """
    cleaned_url = str(url).strip()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # Deduplication safeguard: If an identical scan for this user and URL was recorded
        # within the last 2 seconds (e.g. rapid multi-click or concurrent duplicate requests),
        # return the existing record ID to enforce: ONE user scan action -> ONE database history record.
        cursor.execute("""
            SELECT id FROM scan_history
            WHERE user_id = ? AND url = ? AND prediction = ?
            AND scanned_at >= datetime('now', '-2 seconds')
            ORDER BY id DESC LIMIT 1
        """, (user_id, cleaned_url, str(prediction)))
        recent = cursor.fetchone()
        if recent:
            return recent['id']

        cursor.execute("""
            INSERT INTO scan_history (user_id, url, prediction, confidence)
            VALUES (?, ?, ?, ?)
        """, (user_id, cleaned_url, str(prediction), float(confidence)))
        conn.commit()
        return cursor.lastrowid


