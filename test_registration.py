import os
import sqlite3
from werkzeug.security import check_password_hash
import app
import database

# Fresh test DB setup
database.init_db()
with database.get_db_connection() as conn:
    conn.execute("DELETE FROM users")
    conn.commit()

client = app.app.test_client()

print('--- Test 1: GET / ---')
res = client.get('/')
assert res.status_code == 200, f'GET / failed: {res.status_code}'
assert b'href="/register"' in res.data, 'Register link not found in index.html'
print('Pass: GET / returns 200 and has /register link.')

print('--- Test 2: GET /register ---')
res = client.get('/register')
assert res.status_code == 200, f'GET /register failed: {res.status_code}'
assert b'Create your account' in res.data
assert b'name="name"' in res.data
assert b'name="email"' in res.data
assert b'name="password"' in res.data
assert b'name="confirm_password"' in res.data
assert b'Create Account' in res.data
assert b'Log in' in res.data
print('Pass: GET /register renders form with all required fields.')

print('--- Test 3: POST /register validation errors ---')
# Empty name
res = client.post('/register', json={
    'name': '',
    'email': 'alice@example.com',
    'password': 'Password123!',
    'confirm_password': 'Password123!'
})
assert res.status_code == 400
assert 'Full name' in res.get_json()['errors']['name']
print('Pass: Empty name rejected.')

# Invalid email
res = client.post('/register', json={
    'name': 'Alice Smith',
    'email': 'not-an-email',
    'password': 'Password123!',
    'confirm_password': 'Password123!'
})
assert res.status_code == 400
assert 'email' in res.get_json()['errors']
print('Pass: Invalid email rejected.')

# Short password
res = client.post('/register', json={
    'name': 'Alice Smith',
    'email': 'alice@example.com',
    'password': 'short',
    'confirm_password': 'short'
})
assert res.status_code == 400
assert 'at least 8 characters' in res.get_json()['errors']['password']
print('Pass: Short password rejected.')

# Password mismatch
res = client.post('/register', json={
    'name': 'Alice Smith',
    'email': 'alice@example.com',
    'password': 'Password123!',
    'confirm_password': 'DifferentPassword456!'
})
assert res.status_code == 400
assert 'Passwords do not match' in res.get_json()['errors']['confirm_password']
print('Pass: Password mismatch rejected.')

print('--- Test 4: POST /register success (JSON) ---')
res = client.post('/register', json={
    'name': 'Alice Smith',
    'email': 'Alice@Example.com',
    'password': 'SecurePassword2026!',
    'confirm_password': 'SecurePassword2026!'
})
assert res.status_code == 201
data = res.get_json()
assert data['success'] is True
print('Pass: User successfully registered with status 201.')

print('--- Test 5: Verify SQLite Database Persistence & Password Hashing ---')
conn = database.get_db_connection()
user = conn.execute('SELECT * FROM users WHERE email = ?', ('alice@example.com',)).fetchone()
conn.close()

assert user is not None, 'User not found in SQLite DB'
assert user['name'] == 'Alice Smith'
assert user['email'] == 'alice@example.com'  # normalized lowercase
assert user['password_hash'] != 'SecurePassword2026!', 'CRITICAL: Password stored in plaintext!'
assert check_password_hash(user['password_hash'], 'SecurePassword2026!'), 'Password hash cannot be verified'
assert not check_password_hash(user['password_hash'], 'WrongPassword!'), 'Password hash verified wrong password'
print('Pass: User stored in SQLite. Email normalized. Password NEVER stored in plaintext and securely hashed.')

print('--- Test 6: Duplicate Email Rejection ---')
res = client.post('/register', json={
    'name': 'Alice Clone',
    'email': 'alice@example.com',
    'password': 'AnotherPassword2026!',
    'confirm_password': 'AnotherPassword2026!'
})
assert res.status_code == 400
data = res.get_json()
assert 'already exists' in data['errors']['email']
print('Pass: Duplicate email properly rejected with clear error message.')

print('--- Test 7: Form POST (Traditional non-AJAX submission) ---')
res = client.post('/register', data={
    'name': 'Bob Jones',
    'email': 'bob@example.com',
    'password': 'BobPassword2026!',
    'confirm_password': 'BobPassword2026!'
})
assert res.status_code == 200
assert b'Account Created' in res.data or b'Proceed to Login' in res.data
print('Pass: Traditional form submission handled successfully.')

print('--- Test 8: GET /login (Page 3) ---')
res = client.get('/login')
assert res.status_code == 200
assert b'Welcome back' in res.data or b'Sign In' in res.data or b'Log In' in res.data
print('Pass: GET /login renders login page.')

print('ALL BACKEND & DATABASE TESTS PASSED SUCCESSFULLY! [OK]')
