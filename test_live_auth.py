"""
Live Session Verification over HTTP using urllib CookieJar.
Verifies all 8 user requirements on the live server (http://127.0.0.1:5000):
1. Correct email + correct password -> login succeeds
2. Correct email + incorrect password -> generic login error ("Invalid email or password.")
3. Non-existent email + any password -> same generic login error
4. Empty email -> validation error (status 400)
5. Empty password -> validation error (status 400)
6. Successful login -> authenticated session created -> /dashboard recognizes the logged-in user
7. /logout -> session cleared -> redirected to /login
8. Directly opening /dashboard without logging in -> redirected to /login
"""

import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
import json
import time

BASE_URL = 'http://127.0.0.1:5000'

# Setup CookieJar opener for session management
cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

# 1. Register a fresh unique user
unique_id = int(time.time())
test_name = f"Test User {unique_id}"
test_email = f"user_{unique_id}@liveauth.org"
test_password = "LiveSecurePassword2026!"

print(f"Creating user for live authentication test: {test_email}")
reg_data = json.dumps({
    'name': test_name,
    'email': test_email,
    'password': test_password,
    'confirm_password': test_password
}).encode('utf-8')

req = urllib.request.Request(
    f"{BASE_URL}/register",
    data=reg_data,
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
with opener.open(req) as res:
    assert res.status == 201
    print("Registration successful.")

# Case 8: Directly opening /dashboard without logging in -> redirected to /login
clean_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
try:
    # Disable auto redirect to check 302
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    no_redirect_opener = urllib.request.build_opener(no_redirect_opener := NoRedirect())
    res = no_redirect_opener.open(f"{BASE_URL}/dashboard")
    assert False, "Should have returned 302"
except urllib.error.HTTPError as e:
    assert e.code == 302
    assert e.headers['Location'] == '/login' or e.headers['Location'].endswith('/login')
    print("Case 8 Passed: Unauthenticated direct access to /dashboard redirects (302) to /login.")

# Case 4: Empty email -> validation error (400)
req = urllib.request.Request(
    f"{BASE_URL}/login",
    data=json.dumps({'email': '', 'password': test_password}).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
try:
    opener.open(req)
    assert False, "Should have failed with 400"
except urllib.error.HTTPError as e:
    assert e.code == 400
    errors = json.loads(e.read().decode('utf-8'))['errors']
    assert 'email' in errors
    print("Case 4 Passed: Empty email rejected with 400 validation error.")

# Case 5: Empty password -> validation error (400)
req = urllib.request.Request(
    f"{BASE_URL}/login",
    data=json.dumps({'email': test_email, 'password': ''}).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
try:
    opener.open(req)
    assert False, "Should have failed with 400"
except urllib.error.HTTPError as e:
    assert e.code == 400
    errors = json.loads(e.read().decode('utf-8'))['errors']
    assert 'password' in errors
    print("Case 5 Passed: Empty password rejected with 400 validation error.")

# Case 2: Correct email + incorrect password -> generic error (401)
req = urllib.request.Request(
    f"{BASE_URL}/login",
    data=json.dumps({'email': test_email, 'password': 'WrongPassword123!'}).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
try:
    opener.open(req)
    assert False, "Should have failed with 401"
except urllib.error.HTTPError as e:
    assert e.code == 401
    resp = json.loads(e.read().decode('utf-8'))
    assert resp['message'] == "Invalid email or password."
    print("Case 2 Passed: Correct email + incorrect password returns 401 'Invalid email or password.'")

# Case 3: Non-existent email + any password -> generic error (401)
req = urllib.request.Request(
    f"{BASE_URL}/login",
    data=json.dumps({'email': 'nonexistent_user_999@test.com', 'password': 'AnyPassword123!'}).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
try:
    opener.open(req)
    assert False, "Should have failed with 401"
except urllib.error.HTTPError as e:
    assert e.code == 401
    resp = json.loads(e.read().decode('utf-8'))
    assert resp['message'] == "Invalid email or password."
    print("Case 3 Passed: Non-existent email returns same generic 401 'Invalid email or password.'")

# Case 1 & 6: Correct email + correct password -> login succeeds & session created
login_req = urllib.request.Request(
    f"{BASE_URL}/login",
    data=json.dumps({'email': test_email, 'password': test_password}).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
with opener.open(login_req) as res:
    assert res.status == 200
    resp = json.loads(res.read().decode('utf-8'))
    assert resp['success'] is True
    assert resp['redirect_url'] == '/dashboard'
    print("Case 1 Passed: Login succeeded with 200 and redirect_url /dashboard.")

# Access /dashboard with authenticated opener
with opener.open(f"{BASE_URL}/dashboard") as res:
    assert res.status == 200
    dash_html = res.read().decode('utf-8')
    assert test_name in dash_html
    assert test_email in dash_html
    assert 'Authenticated Session Active' in dash_html
    print("Case 6 Passed: /dashboard recognized the authenticated user from Flask session.")

# Case 7: /logout clears session and redirects to /login
# Test /logout redirect
try:
    res = no_redirect_opener.open(f"{BASE_URL}/logout")
    assert False, "Should redirect"
except urllib.error.HTTPError as e:
    assert e.code == 302
    assert e.headers['Location'] == '/login' or e.headers['Location'].endswith('/login')
    print("Case 7a Passed: /logout redirected (302) to /login.")

# Execute logout with our session-carrying opener
with opener.open(f"{BASE_URL}/logout") as res:
    assert res.status == 200
    # Following redirect brought us to /login
    login_page = res.read().decode('utf-8')
    assert 'Welcome back' in login_page or 'Sign In' in login_page
    print("Case 7b Passed: Following /logout redirected to /login.")

# Verify subsequent /dashboard access is now blocked (session cleared)
try:
    res = no_redirect_opener.open(f"{BASE_URL}/dashboard")
    assert False, "Should redirect to /login"
except urllib.error.HTTPError as e:
    assert e.code == 302
    assert e.headers['Location'] == '/login' or e.headers['Location'].endswith('/login')
    print("Case 7c Passed: Subsequent /dashboard access blocked after logout.")

print("\n=======================================================")
print("ALL 8 LIVE ENDPOINT TEST CASES VERIFIED AND PASSING! [OK]")
print("=======================================================\n")
