"""
PhishGuard — Database Dual-Backend Architecture Unit Tests
Validates:
1. SQLite mode active by default when DATABASE_URL is unset
2. PostgreSQL mode activates when DATABASE_URL is provided
3. Correct exception inheritance (IntegrityError is caught by sqlite3.IntegrityError handlers)
4. PostgreSQL query parameters and serverless connection handling
"""

import os
import unittest
from unittest.mock import patch, MagicMock
import sqlite3
import database


class TestDatabaseDualBackend(unittest.TestCase):
    def setUp(self):
        # Ensure DATABASE_URL is not set by default during testing
        if 'DATABASE_URL' in os.environ:
            del os.environ['DATABASE_URL']

    def test_default_sqlite_mode(self):
        self.assertFalse(database.is_postgres())
        conn = database.get_db_connection()
        self.assertIsInstance(conn, sqlite3.Connection)
        conn.close()

    def test_postgres_mode_detected(self):
        with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://postgres:fake_password@aws-0-us-east-1.pooler.supabase.com:6543/postgres'}):
            self.assertTrue(database.is_postgres())
            self.assertEqual(
                database.get_database_url(),
                'postgresql://postgres:fake_password@aws-0-us-east-1.pooler.supabase.com:6543/postgres'
            )

    def test_integrity_error_inheritance(self):
        """Verify database.IntegrityError is a subclass of sqlite3.IntegrityError for unified error catching."""
        self.assertTrue(issubclass(database.IntegrityError, sqlite3.IntegrityError))
        self.assertTrue(issubclass(database.IntegrityError, database.DatabaseError))

    def test_sqlite_crud_and_isolation(self):
        """Verify full database CRUD cycle with SQLite."""
        database.init_db()
        with database.get_db_connection() as conn:
            conn.execute("DELETE FROM scan_history")
            conn.execute("DELETE FROM users")
            conn.commit()

        # Create user
        uid = database.create_user("Backend Test User", "backend_test@phishguard.test", "hash_abc_123")
        self.assertIsInstance(uid, int)

        # Retrieve user by email (case-insensitive)
        user = database.get_user_by_email("BACKEND_TEST@PHISHGUARD.TEST")
        self.assertIsNotNone(user)
        self.assertEqual(user['name'], "Backend Test User")
        self.assertEqual(user['email'], "backend_test@phishguard.test")

        # Duplicate email raises IntegrityError
        with self.assertRaises(database.IntegrityError):
            database.create_user("Duplicate User", "backend_test@phishguard.test", "another_hash")

        # Retrieve by ID
        user_by_id = database.get_user_by_id(uid)
        self.assertIsNotNone(user_by_id)
        self.assertEqual(user_by_id['id'], uid)

        # Initial stats
        stats = database.get_user_scan_stats(uid)
        self.assertEqual(stats['total_scans'], 0)
        self.assertEqual(stats['phishing_detected'], 0)
        self.assertEqual(stats['legitimate_urls'], 0)

        # Create scan records
        s1 = database.create_scan_record(uid, "https://phish-test.xyz", "Phishing", 0.95)
        s2 = database.create_scan_record(uid, "https://safe-test.org", "Legitimate", 0.99)
        self.assertIsInstance(s1, int)
        self.assertIsInstance(s2, int)

        # Deduplication within 2 seconds
        s1_dup = database.create_scan_record(uid, "https://phish-test.xyz", "Phishing", 0.95)
        self.assertEqual(s1, s1_dup, "Deduplication should return existing scan ID")

        # Updated stats
        stats_updated = database.get_user_scan_stats(uid)
        self.assertEqual(stats_updated['total_scans'], 2)
        self.assertEqual(stats_updated['phishing_detected'], 1)
        self.assertEqual(stats_updated['legitimate_urls'], 1)

        # Recent scans
        recent = database.get_user_recent_scans(uid, limit=5)
        self.assertEqual(len(recent), 2)
        self.assertEqual(recent[0]['url'], "https://safe-test.org")
        self.assertEqual(recent[1]['url'], "https://phish-test.xyz")

    def test_postgres_execution_routing(self):
        """Verify that when DATABASE_URL is set, psycopg is invoked with pooler connection string."""
        with patch.dict(os.environ, {'DATABASE_URL': 'postgresql://postgres.ref:secret@aws-0.pooler.supabase.com:6543/postgres'}):
            with patch('psycopg.connect') as mock_connect:
                mock_conn = MagicMock()
                mock_cursor = MagicMock()
                mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
                mock_connect.return_value.__enter__.return_value = mock_conn

                # Test init_db routes to PostgreSQL schema
                database.init_db()
                self.assertTrue(mock_connect.called)
                executed_calls = [str(call) for call in mock_cursor.execute.call_args_list]
                # Check for PostgreSQL specific types like SERIAL and TIMESTAMPTZ
                self.assertTrue(any("SERIAL PRIMARY KEY" in call for call in executed_calls))
                self.assertTrue(any("TIMESTAMPTZ" in call for call in executed_calls))


if __name__ == '__main__':
    unittest.main()
