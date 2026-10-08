"""
Database management module for PhishGuard.
Supports dual backends:
- Local development: SQLite (phishguard.db)
- Production (Vercel / Supabase): PostgreSQL via psycopg (Transaction Pooler)

Connections are created on-demand and closed per operation to remain safe for
serverless execution environments (Vercel / AWS Lambda) and avoid exhausting poolers.
"""

import os
import sqlite3
from typing import Optional, Any, Dict, List

try:
    import psycopg
    from psycopg.rows import dict_row
    PSYCOPG_AVAILABLE = True
except ImportError:
    psycopg = None
    dict_row = None
    PSYCOPG_AVAILABLE = False

# Path to the local SQLite database file
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phishguard.db')


class DatabaseError(sqlite3.Error):
    """Base exception for PhishGuard database operations across backends."""
    pass


class IntegrityError(sqlite3.IntegrityError, DatabaseError):
    """Raised when unique constraints or foreign key rules are violated."""
    pass


def is_postgres() -> bool:
    """Return True if DATABASE_URL environment variable is configured for PostgreSQL."""
    return bool(os.environ.get('DATABASE_URL', '').strip())


def get_database_url() -> str:
    """Retrieve the DATABASE_URL environment variable."""
    return os.environ.get('DATABASE_URL', '').strip()


def get_db_connection():
    """
    Create and return a database connection.
    - If DATABASE_URL is set: connects to PostgreSQL via psycopg with dict_row factory.
      (Designed for Supabase Transaction Pooler on port 6543).
    - If DATABASE_URL is not set: connects to local SQLite database with sqlite3.Row factory.
    """
    if is_postgres():
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError(
                "DATABASE_URL is configured for PostgreSQL, but psycopg is not installed. "
                "Install psycopg using: pip install psycopg[binary]"
            )
        db_url = get_database_url()
        return psycopg.connect(db_url, row_factory=dict_row)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Initialize database schema if tables do not exist (supports both PostgreSQL and SQLite)."""
    if is_postgres():
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        url TEXT NOT NULL,
                        prediction TEXT NOT NULL,
                        confidence DOUBLE PRECISION,
                        scanned_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id);
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at);
                """)
            conn.commit()
    else:
        conn = get_db_connection()
        try:
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
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
            """)
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
        finally:
            conn.close()


def get_user_by_email(email: str) -> Optional[Any]:
    """Retrieve a user by email using case-insensitive comparison."""
    if not email:
        return None
    normalized_email = email.strip().lower()
    if is_postgres():
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, name, email, password_hash, created_at FROM users WHERE LOWER(email) = LOWER(%s)",
                    (normalized_email,)
                )
                return cursor.fetchone()
    else:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, email, password_hash, created_at FROM users WHERE LOWER(email) = LOWER(?)",
                (normalized_email,)
            )
            return cursor.fetchone()
        finally:
            conn.close()


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
        IntegrityError: If the email already exists
        DatabaseError: For any other database error
    """
    normalized_name = name.strip()
    normalized_email = email.strip().lower()
    if is_postgres():
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
                        (normalized_name, normalized_email, password_hash)
                    )
                    row = cursor.fetchone()
                    conn.commit()
                    return row['id']
        except Exception as e:
            if PSYCOPG_AVAILABLE and isinstance(e, psycopg.IntegrityError):
                raise IntegrityError("An account with this email address already exists. Please log in.") from e
            if PSYCOPG_AVAILABLE and isinstance(e, psycopg.Error):
                raise DatabaseError("A database error occurred while creating your account.") from e
            raise
    else:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (normalized_name, normalized_email, password_hash)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError as e:
            raise IntegrityError("An account with this email address already exists. Please log in.") from e
        except sqlite3.Error as e:
            raise DatabaseError("A database error occurred while creating your account.") from e
        finally:
            conn.close()


def get_user_by_id(user_id: int) -> Optional[Any]:
    """Retrieve a user by their unique primary key ID."""
    if not user_id:
        return None
    if is_postgres():
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, name, email, password_hash, created_at FROM users WHERE id = %s",
                    (user_id,)
                )
                return cursor.fetchone()
    else:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, name, email, password_hash, created_at FROM users WHERE id = ?",
                (user_id,)
            )
            return cursor.fetchone()
        finally:
            conn.close()


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

    if is_postgres():
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'scan_history'"
                )
                if not cursor.fetchone():
                    return default_stats

                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_scans,
                        SUM(CASE WHEN LOWER(prediction) = 'phishing' THEN 1 ELSE 0 END) as phishing_detected,
                        SUM(CASE WHEN LOWER(prediction) = 'legitimate' THEN 1 ELSE 0 END) as legitimate_urls
                    FROM scan_history
                    WHERE user_id = %s
                """, (user_id,))
                row = cursor.fetchone()
                if row:
                    return {
                        'total_scans': int(row['total_scans'] or 0),
                        'phishing_detected': int(row['phishing_detected'] or 0),
                        'legitimate_urls': int(row['legitimate_urls'] or 0)
                    }
                return default_stats
    else:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
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
                    'total_scans': int(row['total_scans'] or 0),
                    'phishing_detected': int(row['phishing_detected'] or 0),
                    'legitimate_urls': int(row['legitimate_urls'] or 0)
                }
            return default_stats
        finally:
            conn.close()


def get_user_recent_scans(user_id: int, limit: int = 5) -> list:
    """
    Retrieve the most recent scans for a specific authenticated user.
    Always filters by user_id to ensure strict privacy and data isolation.
    Returns an empty list if scan_history does not exist or has no records.
    """
    if not user_id:
        return []

    if is_postgres():
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'scan_history'"
                )
                if not cursor.fetchone():
                    return []

                cursor.execute("""
                    SELECT id, user_id, url, prediction, confidence, scanned_at
                    FROM scan_history
                    WHERE user_id = %s
                    ORDER BY scanned_at DESC, id DESC
                    LIMIT %s
                """, (user_id, limit))
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    item = dict(row)
                    if hasattr(item.get('scanned_at'), 'strftime'):
                        item['scanned_at'] = item['scanned_at'].strftime('%Y-%m-%d %H:%M:%S')
                    results.append(item)
                return results
    else:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
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
        finally:
            conn.close()


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
    if is_postgres():
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Deduplication safeguard: within 2 seconds
                cursor.execute("""
                    SELECT id FROM scan_history
                    WHERE user_id = %s AND url = %s AND prediction = %s
                    AND scanned_at >= NOW() - INTERVAL '2 seconds'
                    ORDER BY id DESC LIMIT 1
                """, (user_id, cleaned_url, str(prediction)))
                recent = cursor.fetchone()
                if recent:
                    return recent['id']

                cursor.execute("""
                    INSERT INTO scan_history (user_id, url, prediction, confidence)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (user_id, cleaned_url, str(prediction), float(confidence)))
                row = cursor.fetchone()
                conn.commit()
                return row['id']
    else:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            # Deduplication safeguard: within 2 seconds
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
        finally:
            conn.close()
