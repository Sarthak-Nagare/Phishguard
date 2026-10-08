import urllib.request
import urllib.error
import json

# 1. Test GET /
with urllib.request.urlopen('http://127.0.0.1:5000/') as res:
    html = res.read().decode('utf-8')
    assert 'href="/register"' in html, 'Register link missing on landing page'
    print('1. Live Landing page OK: status', res.status)

# 2. Test GET /register
with urllib.request.urlopen('http://127.0.0.1:5000/register') as res:
    html = res.read().decode('utf-8')
    assert 'Create your account' in html
    assert 'Full Name' in html
    assert 'Email Address' in html
    assert 'Password' in html
    assert 'Confirm Password' in html
    assert 'Create Account' in html
    assert 'Log in' in html
    print('2. Live Registration page OK: status', res.status)

# 3. Test POST /register with empty data (JSON)
req = urllib.request.Request(
    'http://127.0.0.1:5000/register',
    data=json.dumps({'name': '', 'email': '', 'password': '', 'confirm_password': ''}).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
try:
    urllib.request.urlopen(req)
    assert False, 'Should have failed with 400'
except urllib.error.HTTPError as e:
    assert e.code == 400
    errors = json.loads(e.read().decode('utf-8'))['errors']
    assert 'name' in errors and 'email' in errors and 'password' in errors and 'confirm_password' in errors
    print('3. Empty validation rejected as expected: status 400, errors:', list(errors.keys()))

# 4. Test POST /register with successful creation (JSON)
import time
test_email = f"user_{int(time.time())}@cyberguard.org"
req = urllib.request.Request(
    'http://127.0.0.1:5000/register',
    data=json.dumps({
        'name': 'Jane Doe',
        'email': test_email,
        'password': 'SecurePassword2026!',
        'confirm_password': 'SecurePassword2026!'
    }).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
with urllib.request.urlopen(req) as res:
    assert res.status == 201
    resp_data = json.loads(res.read().decode('utf-8'))
    assert resp_data['success'] is True
    print('4. Registration successful: status 201, message:', resp_data['message'])

# 5. Test Duplicate Email
req = urllib.request.Request(
    'http://127.0.0.1:5000/register',
    data=json.dumps({
        'name': 'Duplicate User',
        'email': test_email,
        'password': 'SecurePassword2026!',
        'confirm_password': 'SecurePassword2026!'
    }).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'Accept': 'application/json'}
)
try:
    urllib.request.urlopen(req)
    assert False, 'Should have failed with 400'
except urllib.error.HTTPError as e:
    assert e.code == 400
    resp_data = json.loads(e.read().decode('utf-8'))
    assert 'already exists' in resp_data['errors']['email']
    print('5. Duplicate email rejected: status 400, error:', resp_data['errors']['email'])

# 6. Test GET /login (Page 3)
with urllib.request.urlopen('http://127.0.0.1:5000/login') as res:
    html = res.read().decode('utf-8')
    assert 'Welcome back' in html or 'Sign In' in html
    assert 'Email Address' in html
    assert 'Password' in html
    assert 'href="/register"' in html
    print('6. Live Login page OK: status', res.status)

print('ALL LIVE HTTP ENDPOINT TESTS PASSED!')
