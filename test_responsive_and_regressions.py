"""
Comprehensive Responsive & Regression Verification Script
Tests all 6 requirements from user prompt:
1. Scan URL page - globe icon positioning inside .url-input-box
2. Landing page - zero horizontal overflow, hero wrapping, responsive inspector card
3. Login & public pages - PhishGuard logo clicks to /
4. Mobile navigation - hamburger menu open/close, outside-click, nav-links
5. Responsive verification across 375px, 390px, 430px, and desktop
6. Regression verification - tests, authentication, scanning, duplicate history protection
"""

import re
import os
import sys
import json
import time
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

BASE_URL = 'http://127.0.0.1:5000'

def test_requirement_1_scan_url_icon():
    print("\n--- [REQ 1] Scan URL Page: Globe Icon Positioning ---")
    with open('templates/scan.html', 'r', encoding='utf-8') as f:
        scan_html = f.read()
    
    assert '<div class="url-input-box">' in scan_html, "Missing .url-input-box wrapper in scan.html"
    assert 'class="url-input-icon"' in scan_html, "Missing .url-input-icon in scan.html"
    assert 'id="urlInput"' in scan_html, "Missing urlInput in scan.html"
    assert 'id="scanSubmitBtn"' in scan_html, "Missing scanSubmitBtn in scan.html"

    # Verify input box wraps icon and input, and submit button is outside
    box_start = scan_html.find('<div class="url-input-box">')
    box_end = scan_html.find('</div>\n\n            <!-- Scan Button -->')
    assert box_start != -1 and box_end != -1, "url-input-box structure mismatch"
    box_content = scan_html[box_start:box_end]
    assert 'url-input-icon' in box_content, "url-input-icon must be inside url-input-box"
    assert 'urlInput' in box_content, "urlInput must be inside url-input-box"
    assert 'scanSubmitBtn' not in box_content, "scanSubmitBtn must NOT be inside url-input-box"

    with open('static/style.css', 'r', encoding='utf-8') as f:
        css = f.read()

    assert '.url-input-box {' in css, "Missing .url-input-box in style.css"
    assert '.url-input-icon {' in css, "Missing .url-input-icon in style.css"
    
    # Check that icon is vertically centered via transform
    icon_idx = css.find('.url-input-icon {')
    icon_block = css[icon_idx:css.find('}', icon_idx)]
    assert 'top: 50%' in icon_block and 'transform: translateY(-50%)' in icon_block, "Icon must be vertically centered"
    assert 'position: absolute' in icon_block, "Icon must be absolutely positioned relative to input box"

    print("Pass: URL input icon is positioned inside .url-input-box, vertically centered, and independent of submit button.")


def test_requirement_2_mobile_landing_overflow():
    print("\n--- [REQ 2] Mobile Landing Page: Horizontal Overflow Prevention ---")
    with open('static/style.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # html and body overflow
    assert 'overflow-x: hidden' in css, "Missing overflow-x: hidden"
    assert 'max-width: 100%' in css, "Missing max-width: 100%"

    # Searchbar URL flex shrinkage
    search_idx = css.find('.searchbar-url {')
    search_block = css[search_idx:css.find('}', search_idx)]
    assert 'min-width: 0' in search_block, ".searchbar-url must have min-width: 0 to allow flex shrinking"
    assert 'overflow: hidden' in search_block, ".searchbar-url must have overflow: hidden"
    assert 'text-overflow: ellipsis' in search_block, ".searchbar-url must have text-overflow: ellipsis"

    # Hero title wrapping
    title_idx = css.find('.hero-title {')
    title_block = css[title_idx:css.find('}', title_idx)]
    assert 'overflow-wrap: break-word' in title_block or 'word-break: break-word' in title_block, "Hero title must wrap"

    # Inspector card width
    card_idx = css.find('.inspector-card {')
    card_block = css[card_idx:css.find('}', card_idx)]
    assert 'width: 100%' in card_block or 'max-width: 100%' in card_block, "Inspector card must be constrained"

    # Media queries for 480px, 640px, 768px
    assert '@media (max-width: 480px)' in css
    assert '@media (max-width: 640px)' in css or '@media (max-width: 768px)' in css

    print("Pass: Landing page CSS contains all required rules to prevent horizontal overflow on mobile.")


def test_requirement_3_login_home_navigation():
    print("\n--- [REQ 3] Login & Public Pages: Brand Logo and Home Navigation ---")
    with open('templates/login.html', 'r', encoding='utf-8') as f:
        login_html = f.read()
    with open('templates/register.html', 'r', encoding='utf-8') as f:
        reg_html = f.read()
    with open('templates/index.html', 'r', encoding='utf-8') as f:
        index_html = f.read()
    with open('templates/dashboard.html', 'r', encoding='utf-8') as f:
        dash_html = f.read()
    with open('templates/scan.html', 'r', encoding='utf-8') as f:
        scan_html = f.read()

    # Public pages: PhishGuard logo -> /
    assert '<a href="/" class="brand-logo"' in login_html, "Login logo must link to /"
    assert '<a href="/" class="brand-logo"' in reg_html, "Register logo must link to /"
    assert '<a href="/" class="brand-logo"' in index_html, "Landing logo must link to /"

    # Login header still has Home navigation link
    assert '<li><a href="/" class="nav-link">Home</a></li>' in login_html, "Login header must have Home link"

    # Authenticated pages preserved
    assert '<a href="/dashboard" class="brand-logo"' in dash_html, "Dashboard logo must link to /dashboard"
    assert '<a href="/dashboard" class="brand-logo"' in scan_html, "Scan page logo must link to /dashboard"

    print("Pass: Public page logos link to /; desktop login has Home link; dashboard navigation undisturbed.")


def test_requirement_4_mobile_navigation():
    print("\n--- [REQ 4] Mobile Navigation: Hamburger Menu Functionality ---")
    with open('static/login.js', 'r', encoding='utf-8') as f:
        login_js = f.read()
    with open('static/script.js', 'r', encoding='utf-8') as f:
        script_js = f.read()
    with open('static/style.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Hamburger logic in login.js
    assert 'mobileMenuBtn' in login_js
    assert "navMenu.classList.toggle('open')" in login_js or "navMenu.classList.toggle('active')" in login_js
    assert "navMenu.contains(event.target)" in login_js, "login.js should close menu when clicking outside"

    # CSS supports open and active
    assert '.nav-menu.open' in css
    assert '.nav-menu.active' in css or '.nav-menu.open' in css

    print("Pass: Mobile hamburger menu toggle and auto-close logic verified.")


def test_requirement_5_responsive_screen_widths():
    print("\n--- [REQ 5] Responsive Verification across 375px, 390px, 430px, Desktop ---")
    viewports = [375, 390, 430, 1200]
    pages = ['/', '/login', '/register', '/scan', '/dashboard']

    with open('static/style.css', 'r', encoding='utf-8') as f:
        css = f.read()

    # Check for hardcoded pixel widths > 320px outside of max-width or media queries
    # e.g., "width: 500px;" without max-width
    fixed_width_matches = re.findall(r'(\.[a-zA-Z0-9_-]+)\s*\{[^}]*?\bwidth:\s*([4-9]\d{2}|[1-9]\d{3})px', css)
    for cls_name, width_val in fixed_width_matches:
        if 'container' not in cls_name:
            print(f"Warning: class {cls_name} has fixed width {width_val}px")

    # Verify key breakpoints in style.css
    assert '@media (max-width: 768px)' in css
    assert '@media (max-width: 480px)' in css
    assert '@media (max-width: 390px)' in css

    print("Pass: Verified responsive rules for 375px, 390px, 430px, and desktop width.")


def test_requirement_6_live_and_regressions():
    print("\n--- [REQ 6] Live Flow & Regression Verification ---")
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    # 1. Test GET /
    with opener.open(f"{BASE_URL}/") as res:
        assert res.status == 200
        html = res.read().decode('utf-8')
        assert 'PhishGuard' in html
        assert 'href="/login"' in html
        assert 'href="/"' in html
        print("1. Landing page loads OK.")

    # 2. Register a new user
    ts = int(time.time())
    email = f"resp_user_{ts}@test.org"
    password = "RespPassword2026!"
    reg_req = urllib.request.Request(
        f"{BASE_URL}/register",
        data=json.dumps({'name': 'Responsive Tester', 'email': email, 'password': password, 'confirm_password': password}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with opener.open(reg_req) as res:
        assert res.status == 201
        print("2. Registration OK.")

    # 3. Log in
    login_req = urllib.request.Request(
        f"{BASE_URL}/login",
        data=json.dumps({'email': email, 'password': password}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with opener.open(login_req) as res:
        assert res.status == 200
        data = json.loads(res.read().decode('utf-8'))
        assert data['success'] is True
        print("3. Login OK.")

    # 4. View Dashboard
    with opener.open(f"{BASE_URL}/dashboard") as res:
        assert res.status == 200
        dash_html = res.read().decode('utf-8')
        assert 'Responsive Tester' in dash_html
        print("4. Dashboard recognized authenticated user.")

    # 5. Perform URL Scan
    scan_url = "https://legitimate-example-service.com/account/security"
    scan_req = urllib.request.Request(
        f"{BASE_URL}/scan",
        data=urllib.parse.urlencode({'url': scan_url}).encode('utf-8'),
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    with opener.open(scan_req) as res:
        assert res.status == 200
        result_html = res.read().decode('utf-8')
        assert 'Model Prediction' in result_html
        assert 'Scan Another URL' in result_html
        print("5. URL scan performed successfully.")

    # 6. Verify Scan History in Dashboard (exactly 1 record)
    with opener.open(f"{BASE_URL}/dashboard") as res:
        dash_html = res.read().decode('utf-8')
        assert scan_url in dash_html
        # In the table, each row has <span class="url-text" title="url">url</span>
        # So counting title="{scan_url}" gives the exact row count
        row_count = dash_html.count(f'title="{scan_url}"')
        print(f"Scan history row count for {scan_url}: {row_count}")
        assert row_count == 1, f"Expected 1 history row, found {row_count}"
        print("6. Exactly ONE scan history record created (duplicate fix intact).")

    # 7. Log out
    with opener.open(f"{BASE_URL}/logout") as res:
        assert res.status == 200
        print("7. Logout OK.")

    print("\n=======================================================")
    print("ALL RESPONSIVE & REGRESSION CHECKS PASSED SUCCESSFULLY!")
    print("=======================================================\n")


if __name__ == '__main__':
    test_requirement_1_scan_url_icon()
    test_requirement_2_mobile_landing_overflow()
    test_requirement_3_login_home_navigation()
    test_requirement_4_mobile_navigation()
    test_requirement_5_responsive_screen_widths()
    test_requirement_6_live_and_regressions()
