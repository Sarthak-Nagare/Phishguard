"""
PhishGuard — Web Application Server
Page 2: User Registration & Authentication Foundation

Provides:
- GET /              : Landing page (Page 1)
- GET /register      : User registration page (Page 2)
- POST /register     : User registration form submission & secure account creation
- GET /login         : Temporary placeholder for Page 3
"""

import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash

import database
import scanner

# Initialize Flask application with dedicated templates and static directories
# Restricts public static assets strictly to static/ folder (prevents root file exposure)
app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)

# Secret Key Security Configuration
# In production, SECRET_KEY must be provided via environment variable.
# For local development, generate a cryptographically strong ephemeral random key if not set.
_env_mode = os.environ.get('FLASK_ENV', os.environ.get('ENV', 'development')).lower()
_env_secret = os.environ.get('SECRET_KEY')

if _env_mode == 'production':
    if not _env_secret:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: "
            "SECRET_KEY environment variable is required in production mode."
        )
    app.secret_key = _env_secret
else:
    app.secret_key = _env_secret or secrets.token_hex(32)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
if os.environ.get('SESSION_COOKIE_SECURE', '').lower() in ('1', 'true', 'yes'):
    app.config['SESSION_COOKIE_SECURE'] = True

# Initialize SQLite database on startup
database.init_db()

# --- In-Memory Rate Limiter (Standard Library Only, Zero New Packages) ---
class InMemoryRateLimiter:
    """
    Thread-safe in-memory sliding-window rate limiter using Python standard library.
    Guarantees protection against brute-force attacks and abuse without external packages.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._requests = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            timestamps = [ts for ts in self._requests[key] if ts > cutoff]
            if len(timestamps) >= max_requests:
                self._requests[key] = timestamps
                return False
            timestamps.append(now)
            self._requests[key] = timestamps
            return True

rate_limiter = InMemoryRateLimiter()

def rate_limit(max_requests: int, window_seconds: int, error_message: str):
    """
    Rate limiting decorator for state-changing HTTP requests.
    Automatically bypasses rate limiting during automated test client runs (app.testing).
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if request.method != 'POST':
                return f(*args, **kwargs)

            if app.testing or app.config.get('TESTING'):
                return f(*args, **kwargs)

            client_ip = (
                request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
                .split(',')[0]
                .strip()
            )
            rate_key = f"{request.endpoint}:{client_ip}"

            if not rate_limiter.is_allowed(rate_key, max_requests, window_seconds):
                is_ajax = (
                    request.is_json
                    or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                    or 'application/json' in request.headers.get('Accept', '')
                )
                if is_ajax:
                    return jsonify({
                        'success': False,
                        'message': error_message,
                        'error': error_message
                    }), 429
                return make_response(
                    f"<!DOCTYPE html><html><head><title>Too Many Requests</title></head>"
                    f"<body style='font-family:sans-serif;padding:40px;text-align:center;background:#0f172a;color:#f8fafc;'>"
                    f"<h2>Rate Limit Exceeded</h2><p>{error_message}</p>"
                    f"<p><a href='javascript:history.back()' style='color:#38bdf8;'>Go Back</a></p></body></html>",
                    429
                )
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Email validation regex (RFC 5322 compliant simplified pattern)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')


def login_required(view_func):
    """
    Authentication decorator to protect routes.
    Redirects unauthenticated visitors to /login.
    """
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return decorated_view


def validate_registration_data(name: str, email: str, password: str, confirm_password: str) -> dict:
    """
    Validate registration input data on the backend.
    Returns a dictionary of field-specific errors. Empty dict means valid.
    """
    errors = {}

    # 1. Full Name validation
    if not name or not name.strip():
        errors['name'] = 'Full name is required.'
    elif len(name.strip()) < 2:
        errors['name'] = 'Full name must be at least 2 characters long.'
    elif len(name.strip()) > 100:
        errors['name'] = 'Full name cannot exceed 100 characters.'

    # 2. Email validation
    if not email or not email.strip():
        errors['email'] = 'Email address is required.'
    else:
        trimmed_email = email.strip()
        if len(trimmed_email) > 120:
            errors['email'] = 'Email address cannot exceed 120 characters.'
        elif not EMAIL_REGEX.match(trimmed_email):
            errors['email'] = 'Please enter a valid email address (e.g., name@example.com).'

    # 3. Password validation
    if not password:
        errors['password'] = 'Password is required.'
    elif len(password) < 8:
        errors['password'] = 'Password must be at least 8 characters long.'
    elif len(password) > 128:
        errors['password'] = 'Password cannot exceed 128 characters.'

    # 4. Confirm Password validation
    if not confirm_password:
        errors['confirm_password'] = 'Please confirm your password.'
    elif password != confirm_password:
        errors['confirm_password'] = 'Passwords do not match. Please re-enter them.'

    return errors


@app.after_request
def set_security_headers(response):
    """Add defensive HTTP security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route('/index.html')
@app.route('/')
def home():
    """
    Serve the completed PhishGuard Landing Page (Page 1).
    Explicitly serves the landing page directly with no redirects.
    """
    return render_template('index.html')


# Backward-compatibility routes for direct static asset requests (served safely from static/)
@app.route('/style.css')
def serve_root_style():
    return app.send_static_file('style.css')

@app.route('/script.js')
def serve_root_script():
    return app.send_static_file('script.js')

@app.route('/login.js')
def serve_root_login_js():
    return app.send_static_file('login.js')

@app.route('/register.js')
def serve_root_register_js():
    return app.send_static_file('register.js')


@app.route('/register.html', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window_seconds=60, error_message="Too many registration attempts. Please wait a moment before trying again.")
def register():
    """
    User Registration route (Page 2).
    - GET: Displays the registration form.
    - POST: Validates input, hashes password, and persists new user in SQLite.
    """
    if request.method == 'GET':
        return render_template('register.html', errors={}, form_data={}, success=False)

    # Determine whether incoming request is JSON or traditional Form data
    is_ajax = (
        request.is_json
        or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in request.headers.get('Accept', '')
    )

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        name = payload.get('name', '')
        email = payload.get('email', '')
        password = payload.get('password', '')
        confirm_password = payload.get('confirm_password', '')
    else:
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

    name = str(name).strip()
    email = str(email).strip().lower()
    password = str(password)
    confirm_password = str(confirm_password)

    # 1. Validate fields
    errors = validate_registration_data(name, email, password, confirm_password)

    # 2. Check email uniqueness if email is syntactically valid
    if 'email' not in errors and email:
        try:
            existing_user = database.get_user_by_email(email)
            if existing_user:
                errors['email'] = 'An account with this email address already exists. Please log in.'
        except Exception:
            errors['general'] = 'An error occurred while checking account availability. Please try again.'

    # Return error response if validation failed
    if errors:
        if is_ajax:
            return jsonify({
                'success': False,
                'message': next(iter(errors.values())),
                'errors': errors
            }), 400
        else:
            return render_template(
                'register.html',
                errors=errors,
                form_data={'name': name, 'email': email},
                success=False
            ), 400

    # 3. Securely hash password and store in SQLite
    try:
        password_hash = generate_password_hash(password)
        database.create_user(name=name, email=email, password_hash=password_hash)

        success_message = 'Account created successfully! You can now proceed to login.'

        if is_ajax:
            return jsonify({
                'success': True,
                'message': success_message,
                'redirect_url': '/login'
            }), 201
        else:
            return render_template(
                'register.html',
                errors={},
                form_data={},
                success=True,
                message=success_message
            ), 200

    except (sqlite3.IntegrityError, database.IntegrityError):
        err_msg = 'An account with this email address already exists. Please log in.'
        if is_ajax:
            return jsonify({
                'success': False,
                'message': err_msg,
                'errors': {'email': err_msg}
            }), 400
        else:
            return render_template(
                'register.html',
                errors={'email': err_msg},
                form_data={'name': name, 'email': email},
                success=False
            ), 400

    except (sqlite3.Error, database.DatabaseError):
        # Never expose internal database error details to the user
        err_msg = 'A database error occurred while creating your account. Please try again later.'
        if is_ajax:
            return jsonify({
                'success': False,
                'message': err_msg,
                'errors': {'general': err_msg}
            }), 500
        else:
            return render_template(
                'register.html',
                errors={'general': err_msg},
                form_data={'name': name, 'email': email},
                success=False
            ), 500

    except Exception:
        err_msg = 'An unexpected error occurred. Please try again later.'
        if is_ajax:
            return jsonify({
                'success': False,
                'message': err_msg,
                'errors': {'general': err_msg}
            }), 500
        else:
            return render_template(
                'register.html',
                errors={'general': err_msg},
                form_data={'name': name, 'email': email},
                success=False
            ), 500


@app.route('/login.html', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window_seconds=60, error_message="Too many login attempts. Please wait a moment before trying again.")
def login():
    """
    User Login route (Page 3).
    - GET: Displays the login form (redirects to /dashboard if already logged in).
    - POST: Validates credentials, verifies password hash, and starts an authenticated session.
    """
    if request.method == 'GET':
        if 'user_id' in session:
            existing_user = database.get_user_by_id(session['user_id'])
            if existing_user:
                return redirect(url_for('dashboard'))
        return render_template('login.html', errors={}, form_data={}, error=None)

    # Determine whether incoming request is JSON or traditional Form data
    is_ajax = (
        request.is_json
        or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in request.headers.get('Accept', '')
    )

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        email = payload.get('email', '')
        password = payload.get('password', '')
    else:
        email = request.form.get('email', '')
        password = request.form.get('password', '')

    raw_email = str(email or '').strip()
    raw_password = str(password or '')
    normalized_email = raw_email.lower()

    # 1. Validate that email and password are provided
    errors = {}
    if not raw_email:
        errors['email'] = 'Please enter your email address.'
    if not raw_password:
        errors['password'] = 'Please enter your password.'

    if errors:
        first_err = next(iter(errors.values()))
        if is_ajax:
            return jsonify({
                'success': False,
                'message': first_err,
                'errors': errors
            }), 400
        else:
            return render_template(
                'login.html',
                errors=errors,
                form_data={'email': raw_email},
                error=first_err
            ), 400

    # 2. Find user in the SQLite users table using their email
    user = database.get_user_by_email(normalized_email)

    # 3 & 4. Retrieve stored password hash and verify with secure password hashing system
    # Generic error message prevents revealing whether the email exists in the database
    if not user or not check_password_hash(user['password_hash'], raw_password):
        generic_error = 'Invalid email or password.'
        errors['general'] = generic_error
        if is_ajax:
            return jsonify({
                'success': False,
                'message': generic_error,
                'errors': errors
            }), 401
        else:
            return render_template(
                'login.html',
                errors=errors,
                form_data={'email': raw_email},
                error=generic_error
            ), 401

    # 5 & 6. Credentials correct: create authenticated Flask session and store user identifier
    session.clear()
    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    # 7. Redirect to /dashboard after successful login
    if is_ajax:
        return jsonify({
            'success': True,
            'message': 'Login successful! Redirecting to dashboard...',
            'redirect_url': '/dashboard'
        }), 200
    else:
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """
    Clear the authenticated Flask session and redirect user to /login.
    """
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard.html')
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Authenticated User Dashboard (Page 4).
    Displays user greeting, personal scan statistics, and recent scans.
    Strictly isolated per authenticated user session.
    """
    user_record = database.get_user_by_id(session['user_id'])
    if not user_record:
        session.clear()
        return redirect(url_for('login'))

    # Security: Build safe user dictionary without exposing password_hash or credentials
    safe_user = {
        'id': user_record['id'],
        'name': user_record['name'],
        'email': user_record['email'],
        'created_at': user_record['created_at']
    }

    # Fetch user-isolated statistics and recent scans
    stats = database.get_user_scan_stats(safe_user['id'])
    recent_scans = database.get_user_recent_scans(safe_user['id'], limit=5)

    return render_template(
        'dashboard.html',
        user=safe_user,
        stats=stats,
        recent_scans=recent_scans
    )


@app.route('/scan.html', methods=['GET', 'POST'])
@app.route('/scan', methods=['GET', 'POST'])
@login_required
@rate_limit(max_requests=30, window_seconds=60, error_message="Scan rate limit exceeded. Please wait a moment before scanning another URL.")
def scan():
    """
    URL Scanner route (Page 5).
    - GET: Displays the URL scanning form.
    - POST: Reads and validates the submitted URL, runs the modular analyze_url placeholder,
      and returns the result state without making any network requests or fake predictions.
    """
    user_record = database.get_user_by_id(session['user_id'])
    if not user_record:
        session.clear()
        return redirect(url_for('login'))

    safe_user = {
        'id': user_record['id'],
        'name': user_record['name'],
        'email': user_record['email']
    }

    if request.method == 'GET':
        return render_template(
            'scan.html',
            user=safe_user,
            submitted_url='',
            error=None,
            result=None
        )

    # Determine whether incoming request is JSON or traditional Form data
    is_ajax = (
        request.is_json
        or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        or 'application/json' in request.headers.get('Accept', '')
    )

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        raw_url = payload.get('url', '')
    else:
        raw_url = request.form.get('url', '')

    # 1. Clean whitespace & normalize URL (prepends https:// if no protocol provided)
    raw_input = str(raw_url or '').strip()
    normalized_url = scanner.normalize_url(raw_input) if raw_input else ''

    # 2. Server-side validation of the normalized URL
    is_valid, error_msg = scanner.validate_url(normalized_url)

    if not is_valid:
        if is_ajax:
            return jsonify({
                'success': False,
                'message': error_msg,
                'error': error_msg
            }), 400
        return render_template(
            'scan.html',
            user=safe_user,
            submitted_url=raw_input,
            error=error_msg,
            result=None
        ), 400

    # 3. Real ML Model Analysis using the normalized URL
    try:
        analysis_result = scanner.analyze_url(normalized_url)
        # 4. Persist genuine scan verdict into scan_history for the authenticated user
        database.create_scan_record(
            user_id=safe_user['id'],
            url=normalized_url,
            prediction=analysis_result['prediction'],
            confidence=analysis_result['confidence']
        )
    except Exception:
        err_msg = "An error occurred while analyzing the URL with the ML model. Please try again."
        if is_ajax:
            return jsonify({'success': False, 'message': err_msg, 'error': err_msg}), 500
        return render_template(
            'scan.html',
            user=safe_user,
            submitted_url=normalized_url,
            error=err_msg,
            result=None
        ), 500

    if is_ajax:
        return jsonify({
            'success': True,
            'message': analysis_result['message'],
            'url': normalized_url,
            'result': analysis_result
        }), 200

    return render_template(
        'scan.html',
        user=safe_user,
        submitted_url=normalized_url,
        error=None,
        result=analysis_result
    )




if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # Debug mode is explicitly disabled by default for production safety.
    # Enable only if explicitly requested via FLASK_DEBUG=1 or DEBUG=true in development.
    is_debug = os.environ.get('FLASK_DEBUG', os.environ.get('DEBUG', '0')).lower() in ('1', 'true', 'yes')
    print(f">> PhishGuard server running at http://127.0.0.1:{port}/")
    print(f">> [Page 1] Landing / Home Page : http://127.0.0.1:{port}/")
    print(f">> [Page 2] User Registration   : http://127.0.0.1:{port}/register")
    print(f">> Debug mode: {'ENABLED (Development Only)' if is_debug else 'DISABLED (Production Safe)'}")
    app.run(host='127.0.0.1', port=port, debug=is_debug)
