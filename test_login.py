"""
PhishGuard — Page 3: Login & Authentication Test Suite
Tests all 8 required authentication test cases:
1. Correct email + correct password -> login succeeds
2. Correct email + incorrect password -> generic login error ("Invalid email or password.")
3. Non-existent email + any password -> same generic login error
4. Empty email -> validation error
5. Empty password -> validation error
6. Successful login -> authenticated session created -> /dashboard recognizes the logged-in user
7. /logout -> session cleared -> redirected to /login
8. Directly opening /dashboard without logging in -> redirected to /login
"""

import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

import app
import database

# Initialize DB and clear test users
database.init_db()
with database.get_db_connection() as conn:
    conn.execute("DELETE FROM users")
    conn.commit()

# Insert a known test user with scrypt hashed password
TEST_NAME = "Alice Cyber"
TEST_EMAIL = "alice@phishguard.test"
TEST_PASSWORD = "ValidMasterPassword2026!"
TEST_HASH = generate_password_hash(TEST_PASSWORD)

user_id = database.create_user(name=TEST_NAME, email=TEST_EMAIL, password_hash=TEST_HASH)
print(f"Setup: Created test user id={user_id} email={TEST_EMAIL}")

# Use Flask test client with cookie/session handling (enable testing mode to bypass rate limiter)
app.app.testing = True
app.app.config['TESTING'] = True
client = app.app.test_client()

print("\n--- Test Case 1: GET /login UI & Elements ---")
res = client.get('/login')
assert res.status_code == 200, f"GET /login failed with status {res.status_code}"
html = res.data.decode('utf-8')
assert "PhishGuard" in html, "Branding missing in login.html"
assert 'name="email"' in html, "Email input missing in login.html"
assert 'name="password"' in html, "Password input missing in login.html"
assert "Sign In" in html or "Log In" in html, "Submit button missing in login.html"
assert 'href="/register"' in html, "Link to /register missing in login.html"
assert 'Create one' in html or 'Create Account' in html, "Prompt link text missing"
print("Pass: GET /login renders PhishGuard login UI with all required elements.")

print("\n--- Test Case 2: Validation on Empty Email (Case 4) ---")
# JSON
res = client.post('/login', json={'email': '', 'password': TEST_PASSWORD})
assert res.status_code == 400
data = res.get_json()
assert 'email' in data['errors']
assert 'email address' in data['errors']['email'].lower()
# Form submit
res_form = client.post('/login', data={'email': '', 'password': TEST_PASSWORD})
assert res_form.status_code == 400
assert b'email address' in res_form.data.lower()
print("Pass: Empty email properly rejected with validation error (JSON and Form).")

print("\n--- Test Case 3: Validation on Empty Password (Case 5) ---")
# JSON
res = client.post('/login', json={'email': TEST_EMAIL, 'password': ''})
assert res.status_code == 400
data = res.get_json()
assert 'password' in data['errors']
assert 'password' in data['errors']['password'].lower()
# Form submit
res_form = client.post('/login', data={'email': TEST_EMAIL, 'password': ''})
assert res_form.status_code == 400
assert b'password' in res_form.data.lower()
print("Pass: Empty password properly rejected with validation error (JSON and Form).")

print("\n--- Test Case 4: Correct Email + Incorrect Password (Case 2) ---")
# JSON
res = client.post('/login', json={'email': TEST_EMAIL, 'password': 'WrongPassword123!'})
assert res.status_code == 401
data = res.get_json()
assert data['success'] is False
assert data['message'] == "Invalid email or password."
assert data['errors']['general'] == "Invalid email or password."
# Form submit
res_form = client.post('/login', data={'email': TEST_EMAIL, 'password': 'WrongPassword123!'})
assert res_form.status_code == 401
assert b'Invalid email or password.' in res_form.data
print("Pass: Incorrect password rejected with generic 'Invalid email or password.' error.")

print("\n--- Test Case 5: Non-existent Email + Any Password (Case 3) ---")
# JSON
res = client.post('/login', json={'email': 'nobody@doesnotexist.com', 'password': 'AnyPassword123!'})
assert res.status_code == 401
data = res.get_json()
assert data['success'] is False
assert data['message'] == "Invalid email or password.", "Must use identical generic error"
# Form submit
res_form = client.post('/login', data={'email': 'nobody@doesnotexist.com', 'password': 'AnyPassword123!'})
assert res_form.status_code == 401
assert b'Invalid email or password.' in res_form.data
print("Pass: Non-existent email yields exact same generic message (No account enumeration vulnerability).")

print("\n--- Test Case 6: Directly opening /dashboard without logging in (Case 8) ---")
res = client.get('/dashboard')
assert res.status_code == 302, f"Expected 302 redirect, got {res.status_code}"
assert res.headers['Location'] == '/login' or res.headers['Location'].endswith('/login')
print("Pass: Unauthenticated access to /dashboard safely redirects to /login.")

print("\n--- Test Case 7: Correct Email + Correct Password (Case 1 & 6) ---")
# Perform login with fresh session
res = client.post('/login', json={'email': TEST_EMAIL, 'password': TEST_PASSWORD})
assert res.status_code == 200, f"Expected 200, got {res.status_code}"
data = res.get_json()
assert data['success'] is True
assert data['redirect_url'] == '/dashboard'

# Verify Flask session was created and /dashboard recognizes the user
res_dash = client.get('/dashboard')
assert res_dash.status_code == 200, f"Expected 200 from /dashboard, got {res_dash.status_code}"
dash_html = res_dash.data.decode('utf-8')
assert TEST_NAME in dash_html, f"User name {TEST_NAME} not displayed on dashboard"
assert TEST_EMAIL in dash_html, f"User email {TEST_EMAIL} not displayed on dashboard"
assert 'Authenticated Session Active' in dash_html or 'Protected' in dash_html
assert 'href="/logout"' in dash_html, "Logout link missing on authenticated dashboard"
print("Pass: Login succeeds, authenticated session created, /dashboard recognizes logged-in user.")

print("\n--- Test Case 8: Traditional Form Submit Login ---")
client_form = app.app.test_client()
res = client_form.post('/login', data={'email': TEST_EMAIL, 'password': TEST_PASSWORD}, follow_redirects=True)
assert res.status_code == 200
assert TEST_NAME in res.data.decode('utf-8')
print("Pass: Traditional HTML form submit creates session and redirects to /dashboard.")

print("\n--- Test Case 9: Visiting /login while already logged in ---")
# Client is currently logged in from Test Case 7
res_login_redirect = client.get('/login')
assert res_login_redirect.status_code == 302
assert res_login_redirect.headers['Location'] == '/dashboard' or res_login_redirect.headers['Location'].endswith('/dashboard')
print("Pass: Authenticated user visiting /login is redirected to /dashboard.")

print("\n--- Test Case 10: /logout clears session and redirects to /login (Case 7) ---")
res_logout = client.get('/logout')
assert res_logout.status_code == 302
assert res_logout.headers['Location'] == '/login' or res_logout.headers['Location'].endswith('/login')

# Verify session was cleared by attempting to access /dashboard again
res_dash_after_logout = client.get('/dashboard')
assert res_dash_after_logout.status_code == 302
assert res_dash_after_logout.headers['Location'] == '/login' or res_dash_after_logout.headers['Location'].endswith('/login')
print("Pass: /logout clears session; subsequent access to /dashboard is blocked.")

print("\n=======================================================")
print("ALL 8 USER AUTHENTICATION & LOGIN TESTS PASSED! [100%]")
print("=======================================================\n")
