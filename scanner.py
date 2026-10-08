"""
PhishGuard — URL Validation & Analysis Engine
Page 5: URL Scanner Foundation

Provides:
- validate_url(url: str) -> tuple[bool, Optional[str]]
  Performs defensive server-side URL validation without making network requests.
- analyze_url(url: str) -> dict
  Modular placeholder for future ML model and feature extraction pipeline (Page 6+).
"""

import re
from typing import Tuple, Optional, Dict, Any
from urllib.parse import urlsplit


# Maximum acceptable length for a URL according to web standards
MAX_URL_LENGTH = 2048

# Allowed web protocols
ALLOWED_SCHEMES = ('http', 'https')


def normalize_url(raw_url: str) -> str:
    """
    Normalize an input URL string:
    - If the URL has no scheme (e.g., 'youtube.com', 'www.youtube.com', 'youtube.com/watch?v=123'),
      prepends 'https://'.
    - If the URL already has a valid scheme (e.g., 'https://', 'http://'), preserves it as-is.
    - Strips leading and trailing whitespace.
    """
    if raw_url is None:
        return ""
    cleaned = str(raw_url).strip()
    if not cleaned:
        return ""
    if cleaned.startswith('//'):
        return 'https:' + cleaned
    if cleaned.lower().startswith(('javascript:', 'data:', 'mailto:', 'tel:', 'file:', 'blob:')):
        return cleaned
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', cleaned):
        return cleaned
    return 'https://' + cleaned


def validate_url(raw_url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that an input string is a well-formed, safe web URL.
    
    Checks:
    1. Input is present and non-empty.
    2. Input does not exceed MAX_URL_LENGTH.
    3. Input does not contain internal whitespace.
    4. URL contains a valid HTTP/HTTPS scheme.
    5. URL contains a valid hostname with a domain extension or IP address.
    
    Security note:
    This function performs lexical and structural inspection only.
    It NEVER initiates network requests, DNS lookups, or connections to the target.
    
    Returns:
        (True, None) if valid.
        (False, error_message) if invalid.
    """
    if raw_url is None:
        return False, "Please enter a URL to scan."
        
    cleaned_url = str(raw_url).strip()
    
    # 1. Blank / empty check
    if not cleaned_url:
        return False, "Please enter a URL to scan."
        
    # 2. Maximum length check
    if len(cleaned_url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."
        
    # 3. Disallow internal spaces
    if ' ' in cleaned_url:
        return False, "URL cannot contain spaces. Please enter a valid web address (e.g., https://example.com)."

    # 4. Parse URL structure safely
    try:
        parsed = urlsplit(cleaned_url)
    except Exception:
        return False, "The entered URL could not be parsed. Please check the format."

    # 5. Protocol / Scheme verification
    scheme = (parsed.scheme or '').lower()
    if not scheme:
        return False, "Missing URL protocol. Please include http:// or https:// (e.g., https://example.com)."
        
    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported protocol '{scheme}://'. PhishGuard only analyzes web URLs (http:// or https://)."

    # 6. Hostname / Domain verification
    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid domain name or hostname (e.g., https://example.com)."

    # Reject clearly invalid single-word hostnames (e.g., 'hello', 'abc') unless 'localhost'
    if '.' not in hostname and hostname.lower() != 'localhost':
        return False, "URL must contain a valid domain name with an extension (e.g., https://example.com)."

    # Disallow invalid characters in hostname
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        return False, "URL hostname contains invalid characters."

    return True, None


import predictor


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Analyze a URL using the production PhishGuard ML model (HistGradientBoosting).
    Extracts 41 lexical, structural, and brand-impersonation features and predicts whether
    the URL is Phishing or Legitimate with estimated statistical confidence.
    
    Security note:
    Operates strictly via passive lexical and structural inspection.
    Never executes or sends network requests to the target URL.
    """
    prediction_result = predictor.predict_url(url)
    return {
        'status': 'success',
        'message': f"Analysis complete: URL classified as {prediction_result['prediction']}.",
        'url': prediction_result['url'],
        'prediction': prediction_result['prediction'],
        'confidence': prediction_result['confidence'],
        'confidence_percentage': prediction_result['confidence_percentage'],
        'probabilities': prediction_result['probabilities'],
        'features': prediction_result['features'],
        'model_used': prediction_result['model_used'],
        'model_version': prediction_result.get('model_version', '1.0'),
        'feature_count': prediction_result.get('feature_count', len(prediction_result['features'])),
        'disclaimer': prediction_result['disclaimer']
    }

