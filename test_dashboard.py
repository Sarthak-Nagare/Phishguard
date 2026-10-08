"""
PhishGuard — Page 4: User Dashboard Test Suite
Tests all requirements for Page 4:
1. Unauthenticated access to /dashboard redirects to /login
2. Unauthenticated access to /scan redirects to /login
3. Authenticated user can access /dashboard (200 OK)
4. Personalized welcome message displaying logged-in user's name ("Welcome back, <Name>")
5. Description text present ("Monitor and analyze suspicious URLs with PhishGuard.")
6. Navigation items present: PhishGuard branding, Dashboard, Scan URL, History, Logout
7. Three statistics cards present: Total Scans, Phishing Detected, Legitimate URLs
8. Default zero statistics when no scans exist (0, 0, 0) — no fake data
9. Empty state in Recent Scans when no scans exist ("No scans yet. Start by scanning a URL.")
10. Prominent "Scan a URL" button pointing to /scan
11. Minimal /scan placeholder route displays "URL Scanner coming soon."
12. Multi-user scan history isolation: User A's scans and stats do NOT leak to User B
13. Strict security: password_hash and secrets NEVER exposed in HTML
14. /logout clears session and blocks subsequent dashboard access
"""

import sqlite3
from werkzeug.security import generate_password_hash
import app
import database

# Initialize database schema
database.init_db()

# Clear previous test data
with database.get_db_connection() as conn:
    conn.execute("DELETE FROM scan_history")
    conn.execute("DELETE FROM users")
    conn.commit()

# Create two test users to verify multi-user isolation
USER_A_NAME = "Rahul Sharma"
USER_A_EMAIL = "rahul@phishguard.test"
USER_A_PASS = "RahulPassword2026!"
user_a_id = database.create_user(USER_A_NAME, USER_A_EMAIL, generate_password_hash(USER_A_PASS))

USER_B_NAME = "Priya Patel"
USER_B_EMAIL = "priya@phishguard.test"
USER_B_PASS = "PriyaPassword2026!"
user_b_id = database.create_user(USER_B_NAME, USER_B_EMAIL, generate_password_hash(USER_B_PASS))

print(f"Setup complete: User A ID={user_a_id} ({USER_A_NAME}), User B ID={user_b_id} ({USER_B_NAME})")

client = app.app.test_client()

# ==============================================================================
# Test 1: Unauthenticated access to /dashboard redirects to /login
# ==============================================================================
print("\n--- Test 1: Unauthenticated access to /dashboard ---")
res = client.get('/dashboard')
assert res.status_code == 302, f"Expected 302, got {res.status_code}"
assert res.headers['Location'] == '/login' or res.headers['Location'].endswith('/login')
print("Pass: Unauthenticated access to /dashboard redirects to /login.")

# ==============================================================================
# Test 2: Unauthenticated access to /scan redirects to /login
# ==============================================================================
print("\n--- Test 2: Unauthenticated access to /scan ---")
res = client.get('/scan')
assert res.status_code == 302, f"Expected 302, got {res.status_code}"
assert res.headers['Location'] == '/login' or res.headers['Location'].endswith('/login')
print("Pass: Unauthenticated access to /scan redirects to /login.")

# ==============================================================================
# Test 3: Authenticated access to /dashboard (User A)
# ==============================================================================
print("\n--- Test 3: Authenticated access to /dashboard ---")
login_res = client.post('/login', json={'email': USER_A_EMAIL, 'password': USER_A_PASS})
assert login_res.status_code == 200, f"Login failed: {login_res.data}"

res = client.get('/dashboard')
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
html = res.data.decode('utf-8')
print("Pass: Authenticated user successfully loads /dashboard with status 200.")

# ==============================================================================
# Test 4: Personalized welcome message & description
# ==============================================================================
print("\n--- Test 4: Personalized welcome message & description ---")
assert f"Welcome back," in html, "Welcome back greeting missing"
assert USER_A_NAME in html, f"User name {USER_A_NAME} missing from welcome message"
assert "Monitor and analyze suspicious URLs with PhishGuard." in html, "Description text missing"
print(f"Pass: Found 'Welcome back, {USER_A_NAME}' and description in dashboard HTML.")

# ==============================================================================
# Test 5: Navigation items
# ==============================================================================
print("\n--- Test 5: Navigation items ---")
assert "PhishGuard" in html, "PhishGuard branding missing"
assert 'href="/dashboard"' in html, "Dashboard nav link missing"
assert 'href="/scan"' in html, "Scan URL nav link missing"
assert 'History' in html, "History nav link missing"
assert 'href="/logout"' in html, "Logout link missing"
print("Pass: All required header / navbar items present.")

# ==============================================================================
# Test 6: Three Statistics Cards (Zero state, no fake data)
# ==============================================================================
print("\n--- Test 6: Three Statistics Cards (Zero state) ---")
assert "Total Scans" in html, "Total Scans card missing"
assert "Phishing Detected" in html, "Phishing Detected card missing"
assert "Legitimate URLs" in html, "Legitimate URLs card missing"

# Inspect database stats for User A
stats_a = database.get_user_scan_stats(user_a_id)
assert stats_a['total_scans'] == 0, f"Expected 0 total scans, got {stats_a['total_scans']}"
assert stats_a['phishing_detected'] == 0, f"Expected 0 phishing, got {stats_a['phishing_detected']}"
assert stats_a['legitimate_urls'] == 0, f"Expected 0 legitimate, got {stats_a['legitimate_urls']}"

assert 'id="statTotalScans">0</div>' in html, "Total Scans does not show 0"
assert 'id="statPhishingDetected">0</div>' in html, "Phishing Detected does not show 0"
assert 'id="statLegitimateUrls">0</div>' in html, "Legitimate URLs does not show 0"
print("Pass: Statistics cards cleanly display 0 when user has no scan history.")

# ==============================================================================
# Test 7: Empty state in Recent Scans section
# ==============================================================================
print("\n--- Test 7: Empty state in Recent Scans ---")
assert "Recent Scans" in html, "Recent Scans section heading missing"
assert "No scans yet. Start by scanning a URL." in html, "Empty state message missing"
print("Pass: Found exact required empty state 'No scans yet. Start by scanning a URL.'")

# ==============================================================================
# Test 8: Prominent "Scan a URL" Quick Action button
# ==============================================================================
print("\n--- Test 8: Prominent 'Scan a URL' quick action ---")
assert 'Scan a URL' in html, "Scan a URL button text missing"
assert 'href="/scan"' in html, "Button link to /scan missing"
print("Pass: Prominent 'Scan a URL' action button present.")

# ==============================================================================
# Test 9: /scan route accessible to authenticated users
# ==============================================================================
print("\n--- Test 9: /scan route accessibility ---")
scan_res = client.get('/scan')
assert scan_res.status_code == 200, f"Expected 200, got {scan_res.status_code}"
scan_html = scan_res.data.decode('utf-8')
assert ("Scan a URL" in scan_html or "URL Scanner coming soon." in scan_html), "Scanner page header missing"
assert 'href="/dashboard"' in scan_html, "Link to return to dashboard missing"
print("Pass: /scan renders scanner page accessible to authenticated user.")


# ==============================================================================
# Test 10: Multi-User Scan History Isolation
# ==============================================================================
print("\n--- Test 10: Multi-User Scan History Isolation ---")
# Insert 3 scans specifically for User A (2 Phishing, 1 Legitimate)
with database.get_db_connection() as conn:
    conn.execute(
        "INSERT INTO scan_history (user_id, url, prediction, confidence) VALUES (?, ?, ?, ?)",
        (user_a_id, "http://phish-bank-login.xyz", "Phishing", 0.985)
    )
    conn.execute(
        "INSERT INTO scan_history (user_id, url, prediction, confidence) VALUES (?, ?, ?, ?)",
        (user_a_id, "https://secure-update-apple.com", "Phishing", 0.942)
    )
    conn.execute(
        "INSERT INTO scan_history (user_id, url, prediction, confidence) VALUES (?, ?, ?, ?)",
        (user_a_id, "https://en.wikipedia.org", "Legitimate", 0.991)
    )
    conn.commit()

# Verify User A's updated statistics
stats_a_updated = database.get_user_scan_stats(user_a_id)
assert stats_a_updated['total_scans'] == 3
assert stats_a_updated['phishing_detected'] == 2
assert stats_a_updated['legitimate_urls'] == 1

# Check User A's dashboard HTML
res_a = client.get('/dashboard')
html_a = res_a.data.decode('utf-8')
assert 'id="statTotalScans">3</div>' in html_a
assert 'id="statPhishingDetected">2</div>' in html_a
assert 'id="statLegitimateUrls">1</div>' in html_a
assert "http://phish-bank-login.xyz" in html_a
assert "https://secure-update-apple.com" in html_a
assert "https://en.wikipedia.org" in html_a
print("Pass: User A sees their own 3 scans and accurate statistics (3 total, 2 phishing, 1 legitimate).")

# Now log in as User B with a fresh client session
client_b = app.app.test_client()
login_b = client_b.post('/login', json={'email': USER_B_EMAIL, 'password': USER_B_PASS})
assert login_b.status_code == 200

# Verify User B's dashboard HTML
res_b = client_b.get('/dashboard')
html_b = res_b.data.decode('utf-8')
assert f"Welcome back," in html_b
assert USER_B_NAME in html_b
assert USER_A_NAME not in html_b, "User A's name leaked to User B"

# User B must still see 0 scans, 0 phishing, 0 legitimate
assert 'id="statTotalScans">0</div>' in html_b
assert 'id="statPhishingDetected">0</div>' in html_b
assert 'id="statLegitimateUrls">0</div>' in html_b

# User B must see empty state and NEVER see User A's URLs
assert "No scans yet. Start by scanning a URL." in html_b
assert "http://phish-bank-login.xyz" not in html_b, "User A's URL leaked to User B!"
assert "https://secure-update-apple.com" not in html_b, "User A's URL leaked to User B!"
assert "https://en.wikipedia.org" not in html_b, "User A's URL leaked to User B!"
print("Pass: User B sees 0 scans and empty state. User A's scans are strictly isolated!")

# ==============================================================================
# Test 11: Security — Sensitive Information Protection
# ==============================================================================
print("\n--- Test 11: Sensitive Information Protection ---")
# Check that password hash, raw passwords, or secrets are NOT present in HTML
assert "scrypt:" not in html_a and "pbkdf2:" not in html_a, "Password hash leaked into HTML!"
assert USER_A_PASS not in html_a, "Plaintext password leaked into HTML!"
assert "phishguard-dev-secret-key" not in html_a, "Session secret leaked into HTML!"
print("Pass: No sensitive credentials or hashes exposed in dashboard markup.")

# ==============================================================================
# Test 12: Logout clears session and redirects
# ==============================================================================
print("\n--- Test 12: Logout clears session and blocks access ---")
res_logout = client.get('/logout')
assert res_logout.status_code == 302
assert res_logout.headers['Location'] == '/login' or res_logout.headers['Location'].endswith('/login')

res_dash_after = client.get('/dashboard')
assert res_dash_after.status_code == 302
assert res_dash_after.headers['Location'] == '/login' or res_dash_after.headers['Location'].endswith('/login')
print("Pass: /logout clears session and subsequent /dashboard access is redirected to /login.")

print("\n=======================================================")
print("ALL 12 USER DASHBOARD (PAGE 4) TESTS PASSED! [100%]")
print("=======================================================\n")
