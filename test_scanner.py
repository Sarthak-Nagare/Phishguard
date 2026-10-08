"""
PhishGuard — URL Scanner & ML Integration Test Suite
Validates:
1. Unauthenticated protection (GET & POST /scan -> redirect to /login)
2. Authenticated Scanner UI rendering (GET /scan) with updated placeholder and helper text
3. URL Normalization:
   - Prepends https:// when no protocol is provided (e.g. youtube.com, www.youtube.com, youtube.com/watch?v=test)
   - Preserves valid existing schemes (e.g. https://youtube.com, http://youtube.com)
   - Validates the normalized URL after normalization
   - Rejects invalid inputs (e.g. invalid random text, empty/whitespace, unsupported protocols)
4. ML inference and database persistence using the NORMALIZED URL
5. Dashboard synchronization & multi-user data isolation
6. XSS protection and AJAX support
"""

import unittest
from werkzeug.security import generate_password_hash
import app
import database
import scanner


class TestScannerMLIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.app.config['TESTING'] = True
        app.app.testing = True
        database.init_db()

    def setUp(self):
        # Reset database tables for clean test state
        with database.get_db_connection() as conn:
            conn.execute("DELETE FROM scan_history")
            conn.execute("DELETE FROM users")
            conn.commit()

        # Create two test users for isolation testing
        self.user1_email = "alice@phishguard.test"
        self.user1_pass = "SecurePass123!"
        self.user1_id = database.create_user("Alice", self.user1_email, generate_password_hash(self.user1_pass))

        self.user2_email = "bob@phishguard.test"
        self.user2_pass = "SecurePass456!"
        self.user2_id = database.create_user("Bob", self.user2_email, generate_password_hash(self.user2_pass))

        self.client = app.app.test_client()

    def login_user(self, email, password):
        return self.client.post('/login', json={'email': email, 'password': password})

    # 1. Unauthenticated access redirect
    def test_unauthenticated_access_redirects(self):
        res_get = self.client.get('/scan')
        self.assertEqual(res_get.status_code, 302)
        self.assertTrue(res_get.headers['Location'].endswith('/login'))

        res_post = self.client.post('/scan', data={'url': 'https://example.com'})
        self.assertEqual(res_post.status_code, 302)
        self.assertTrue(res_post.headers['Location'].endswith('/login'))

    # 2. Authenticated GET /scan renders UI with updated placeholder
    def test_authenticated_get_scan_ui(self):
        self.login_user(self.user1_email, self.user1_pass)
        res = self.client.get('/scan')
        self.assertEqual(res.status_code, 200)
        html = res.data.decode('utf-8')
        self.assertIn("Scan a URL", html)
        self.assertIn('placeholder="Enter a URL (e.g. youtube.com or https://youtube.com)"', html)
        self.assertIn("Scan URL", html)
        self.assertIn('href="/dashboard"', html)
        self.assertNotIn("Zero-Contact Scanning", html)
        self.assertIn("youtube.com &bull; www.youtube.com &bull; https://youtube.com", html)

    # 3. URL Normalization and Acceptance Test Cases
    def test_url_normalization_cases(self):
        self.login_user(self.user1_email, self.user1_pass)

        # A. youtube.com -> normalizes to https://youtube.com
        res = self.client.post('/scan', data={'url': 'youtube.com'})
        self.assertEqual(res.status_code, 200)
        self.assertIn("https://youtube.com", res.data.decode('utf-8'))

        # B. www.youtube.com -> normalizes to https://www.youtube.com
        res = self.client.post('/scan', data={'url': 'www.youtube.com'})
        self.assertEqual(res.status_code, 200)
        self.assertIn("https://www.youtube.com", res.data.decode('utf-8'))

        # C. https://youtube.com -> preserves scheme
        res = self.client.post('/scan', data={'url': 'https://youtube.com'})
        self.assertEqual(res.status_code, 200)
        self.assertIn("https://youtube.com", res.data.decode('utf-8'))

        # D. http://youtube.com -> preserves scheme
        res = self.client.post('/scan', data={'url': 'http://youtube.com'})
        self.assertEqual(res.status_code, 200)
        self.assertIn("http://youtube.com", res.data.decode('utf-8'))

        # E. youtube.com/watch?v=test -> normalizes to https://youtube.com/watch?v=test
        res = self.client.post('/scan', data={'url': 'youtube.com/watch?v=test'})
        self.assertEqual(res.status_code, 200)
        self.assertIn("https://youtube.com/watch?v=test", res.data.decode('utf-8'))

    # 4. Server-side validation rejects invalid and empty inputs
    def test_validation_errors(self):
        self.login_user(self.user1_email, self.user1_pass)

        # Blank / Empty inputs
        for empty_in in ['', '   ', '\t\n']:
            res = self.client.post('/scan', data={'url': empty_in})
            self.assertEqual(res.status_code, 400)
            self.assertIn(b"Please enter a URL to scan", res.data)

        # Invalid random text containing spaces
        res = self.client.post('/scan', data={'url': 'invalid random text'})
        self.assertEqual(res.status_code, 400)
        self.assertIn(b"cannot contain spaces", res.data)

        # Single-word hostname without extension
        res = self.client.post('/scan', data={'url': 'invalidtext'})
        self.assertEqual(res.status_code, 400)
        self.assertIn(b"domain name with an extension", res.data)

        # Unsupported protocol
        for bad_proto in ['ftp://example.com', 'javascript:alert(1)', 'data:text/html,test']:
            res = self.client.post('/scan', data={'url': bad_proto})
            self.assertEqual(res.status_code, 400)
            self.assertIn(b"Unsupported protocol", res.data)

        # Malformed hostname
        for bad_host in ['http://', 'https://', 'http:///path']:
            res = self.client.post('/scan', data={'url': bad_host})
            self.assertEqual(res.status_code, 400)

    # 5. Database persistence uses normalized URL
    def test_scan_persisted_to_database_with_normalized_url(self):
        self.login_user(self.user1_email, self.user1_pass)
        input_url = "example.com/test-persistence"
        expected_norm = "https://example.com/test-persistence"

        res = self.client.post('/scan', data={'url': input_url})
        self.assertEqual(res.status_code, 200)

        # Verify scan record in SQLite has the normalized URL
        recent_scans = database.get_user_recent_scans(self.user1_id)
        self.assertEqual(len(recent_scans), 1)
        self.assertEqual(recent_scans[0]['url'], expected_norm)
        self.assertIn(recent_scans[0]['prediction'], ['Phishing', 'Legitimate'])
        self.assertGreaterEqual(recent_scans[0]['confidence'], 0.5)

    # 6. Dashboard metrics reflect new scans
    def test_dashboard_metrics_updated_after_scan(self):
        self.login_user(self.user1_email, self.user1_pass)

        # Initial dashboard has 0 scans
        dash_res = self.client.get('/dashboard')
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn("No scans yet. Start by scanning a URL.", dash_res.data.decode('utf-8'))

        # Perform 2 scans (one normalized, one with explicit scheme)
        self.client.post('/scan', data={'url': 'wikipedia.org'})
        self.client.post('/scan', data={'url': 'http://secure-paypal-update-login-verify-account.com'})

        # Check updated dashboard
        dash_res_updated = self.client.get('/dashboard')
        dash_html = dash_res_updated.data.decode('utf-8')

        stats = database.get_user_scan_stats(self.user1_id)
        self.assertEqual(stats['total_scans'], 2)
        self.assertEqual(stats['phishing_detected'] + stats['legitimate_urls'], 2)

        # Dashboard table contains both normalized URLs
        self.assertIn("https://wikipedia.org", dash_html)
        self.assertIn("http://secure-paypal-update-login-verify-account.com", dash_html)

    # 7. User data isolation
    def test_user_data_isolation(self):
        # Alice scans a URL
        self.login_user(self.user1_email, self.user1_pass)
        self.client.post('/scan', data={'url': 'alice-private-domain.org'})

        # Log out Alice
        self.client.get('/logout')

        # Log in Bob
        self.login_user(self.user2_email, self.user2_pass)
        bob_dash = self.client.get('/dashboard')
        bob_html = bob_dash.data.decode('utf-8')

        # Bob should NOT see Alice's scan
        self.assertNotIn("https://alice-private-domain.org", bob_html)
        self.assertIn("No scans yet. Start by scanning a URL.", bob_html)

        bob_stats = database.get_user_scan_stats(self.user2_id)
        self.assertEqual(bob_stats['total_scans'], 0)

    # 8. XSS protection in rendered output
    def test_xss_protection(self):
        self.login_user(self.user1_email, self.user1_pass)
        xss_url = "example.com/search?q=<script>alert('xss')</script>"
        res = self.client.post('/scan', data={'url': xss_url})
        self.assertEqual(res.status_code, 200)
        html = res.data.decode('utf-8')
        self.assertNotIn("<script>alert('xss')</script>", html)
        self.assertIn("&lt;script&gt;", html)

    # 9. AJAX / JSON POST support with normalized URL
    def test_ajax_scan_endpoint(self):
        self.login_user(self.user1_email, self.user1_pass)
        res = self.client.post('/scan', json={'url': 'github.com/torvalds/linux'})
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertTrue(json_data['success'])
        self.assertEqual(json_data['url'], 'https://github.com/torvalds/linux')
        self.assertIn('result', json_data)
        self.assertIn(json_data['result']['prediction'], ['Phishing', 'Legitimate'])
        self.assertIn('probabilities', json_data['result'])
        self.assertIn('features', json_data['result'])

    # 10. Regression Test: Rapid duplicate scans produce exactly ONE database history record
    def test_rapid_duplicate_scan_prevention(self):
        self.login_user(self.user1_email, self.user1_pass)
        test_url = "https://yourtube.com"

        # Simulate rapid multi-click (3 consecutive requests within the same second)
        res1 = self.client.post('/scan', data={'url': test_url})
        res2 = self.client.post('/scan', data={'url': test_url})
        res3 = self.client.post('/scan', data={'url': test_url})

        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res3.status_code, 200)

        # Verify scan_history table contains exactly ONE entry for this URL
        scans = database.get_user_recent_scans(self.user1_id, limit=10)
        matching_scans = [s for s in scans if s['url'] == test_url]
        self.assertEqual(
            len(matching_scans), 1,
            f"Expected exactly 1 history record for rapid scan, got {len(matching_scans)}"
        )

        # Verify dashboard statistics also reflect exactly 1 scan
        stats = database.get_user_scan_stats(self.user1_id)
        self.assertEqual(stats['total_scans'], 1)

    # 11. Regression Test: Scanning distinct URLs creates distinct records and dashboard stability
    def test_distinct_scans_and_dashboard_stability(self):
        self.login_user(self.user1_email, self.user1_pass)

        # Scan first URL
        self.client.post('/scan', data={'url': 'https://wikipedia.org'})
        scans_after_first = database.get_user_recent_scans(self.user1_id)
        self.assertEqual(len(scans_after_first), 1)

        # Scan second distinct URL
        self.client.post('/scan', data={'url': 'https://python.org'})
        scans_after_second = database.get_user_recent_scans(self.user1_id)
        self.assertEqual(len(scans_after_second), 2)

        # Refresh dashboard multiple times
        for _ in range(3):
            dash_res = self.client.get('/dashboard')
            self.assertEqual(dash_res.status_code, 200)
            dash_html = dash_res.data.decode('utf-8')
            self.assertIn("https://wikipedia.org", dash_html)
            self.assertIn("https://python.org", dash_html)

        # Records in database remain exactly 2
        scans_final = database.get_user_recent_scans(self.user1_id)
        self.assertEqual(len(scans_final), 2)
        stats = database.get_user_scan_stats(self.user1_id)
        self.assertEqual(stats['total_scans'], 2)


if __name__ == '__main__':
    unittest.main()
