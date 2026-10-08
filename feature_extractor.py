"""
PhishGuard — URL Feature Extraction Pipeline
Engineered with advanced lexical, structural, and brand-impersonation representation.

Features Extracted (41 Total):
--------------------------------------------------------------------------------
1. Basic URL Structure:
   - url_length                     : Total character length of URL
   - hostname_length                : Character length of hostname/netloc
   - path_length                    : Character length of path component
   - query_length                   : Character length of query string
   - fragment_length                : Character length of fragment (#...)
   - dot_count                      : Total count of dots (.) in URL
   - subdomain_count                : Number of subdomain levels in hostname
   - path_segment_count             : Number of '/' segments in path
   - query_param_count              : Number of query parameters (?key=val)

2. Character Statistics & Obfuscation:
   - digit_count                    : Total count of numeric digits (0-9)
   - percentage_numeric_chars       : Percentage of numeric characters in URL
   - hyphen_count                   : Total count of hyphens (-) in URL
   - has_hyphen_in_domain           : Binary flag (1 if hyphen in domain/hostname, else 0)
   - special_char_count             : Total count of special characters (@, _, =, ?, &, %, +, ~, !, $, *, ;)
   - at_symbol_count                : Count of '@' symbols in URL
   - suspicious_separator_count     : Count of consecutive hyphens (--), underscores, or colons
   - consecutive_char_repeat_max    : Maximum run length of identical consecutive characters
   - has_repeated_char_run          : Binary flag (1 if >= 3 consecutive identical characters)

3. Domain & Hostname Characteristics:
   - domain_name_length             : Character length of registered domain name (SLD)
   - domain_entropy                 : Shannon entropy of registered domain name
   - hostname_entropy               : Shannon entropy of full hostname
   - url_entropy                    : Shannon entropy across the entire URL string
   - suspicious_subdomain_structure : Binary flag (1 if subdomain has digits, hyphens, or depth > 2)
   - unusual_domain_patterns        : Binary flag (1 if domain starts/ends with hyphen or has double hyphens)
   - has_ip_address                 : Binary flag (1 if hostname is raw IPv4/IPv6, else 0)
   - tld_length                     : Character length of top-level domain
   - tld_popularity                 : Binary flag (1 if common TLD: com, net, org, edu, gov)

4. Security & Protocol Indicators:
   - https_flag                     : Binary flag (1 if scheme is https, else 0)
   - suspicious_scheme              : Binary flag (1 if scheme is not http/https)
   - percent_encoding_count         : Count of '%' characters in URL
   - has_encoded_chars              : Binary flag (1 if URL contains percent-encoded bytes)
   - suspicious_file_extension      : Binary flag (1 if path ends with dangerous executable/script ext)

5. Content-Independent Lexical Keywords:
   - suspicious_keyword_count       : Count of security/credential keywords (login, verify, account, etc.)
   - keyword_in_domain              : Binary flag (1 if any credential keyword appears in hostname)
   - keyword_in_path                : Binary flag (1 if any credential keyword appears in path/query)

6. Typo-Squatting, Brand Impersonation & Similarity Patterns:
   - has_leetspeak_substitution     : Binary flag (1 if digits replace letters, e.g. 0->o, 1->l, 3->e)
   - min_brand_edit_distance        : Minimum Levenshtein edit distance from domain to major reference brands
   - is_brand_typo                  : Binary flag (1 if domain is a 1- or 2-edit mutation of a major brand)
   - brand_in_subdomain_or_path     : Binary flag (1 if a major brand token appears in subdomain, path, or compound host)
   - suspicious_hyphen_brand        : Binary flag (1 if a major brand is adjacent to a hyphen in the domain)
   - vowel_consonant_ratio          : Ratio of vowels to consonants in domain name

IMPORTANT SECURITY & PRIVACY PRINCIPLES:
- All features are computed strictly in-memory from the raw URL string.
- Zero network requests, DNS lookups, or target website visits.
- Fully deterministic and identical during training and live inference.
"""

import re
import math
import collections
import urllib.parse
from typing import Dict, List, Any, Optional

# Reference list of common high-profile legitimate brands targeted by phishing.
# Note: Used strictly as a source for feature engineering (edit distance, token presence).
# Does NOT act as an allowlist or blocklist.
REFERENCE_BRANDS: List[str] = [
    'google', 'youtube', 'facebook', 'microsoft', 'apple', 'amazon', 'netflix',
    'paypal', 'instagram', 'twitter', 'linkedin', 'whatsapp', 'telegram', 'yahoo',
    'ebay', 'spotify', 'adobe', 'dropbox', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'walmart', 'roblox', 'steam', 'discord', 'github', 'icloud',
    'outlook', 'office365'
]

# Content-independent credential & security keywords commonly observed in phishing attacks
SUSPICIOUS_KEYWORDS = {
    'login', 'signin', 'verify', 'verification', 'account', 'secure',
    'update', 'password', 'banking', 'confirm', 'authenticate', 'wallet', 'payment'
}

# Popular Top-Level Domains (TLDs)
POPULAR_TLDS = {'com', 'net', 'org', 'edu', 'gov'}

# Suspicious file extensions commonly found in phishing / payload delivery URLs
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bin', '.vmp', '.apk', '.scr', '.jar', '.bat', '.cmd', '.msi', '.pif', '.dll'
}

# Regex to detect raw IPv4 addresses
IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# Leetspeak digit substitutions commonly used to deceive users (e.g. g00gle, paypa1)
LEETSPEAK_PATTERNS = [
    r'[a-z]0[a-z]',  # 0 for o
    r'[a-z]1[a-z]',  # 1 for l or i
    r'[a-z]3[a-z]',  # 3 for e
    r'[a-z]5[a-z]',  # 5 for s
]
LEETSPEAK_REGEX = re.compile('|'.join(LEETSPEAK_PATTERNS), re.IGNORECASE)

# Special character set
SPECIAL_CHARS = set("@_-=?&%+~!$*;#")

# Complete ordered list of 41 features for the machine-learning model
FEATURE_NAMES: List[str] = [
    'url_length',
    'hostname_length',
    'path_length',
    'query_length',
    'fragment_length',
    'dot_count',
    'subdomain_count',
    'path_segment_count',
    'query_param_count',
    'digit_count',
    'percentage_numeric_chars',
    'hyphen_count',
    'has_hyphen_in_domain',
    'special_char_count',
    'at_symbol_count',
    'suspicious_separator_count',
    'consecutive_char_repeat_max',
    'has_repeated_char_run',
    'domain_name_length',
    'domain_entropy',
    'hostname_entropy',
    'url_entropy',
    'suspicious_subdomain_structure',
    'unusual_domain_patterns',
    'has_ip_address',
    'tld_length',
    'tld_popularity',
    'https_flag',
    'suspicious_scheme',
    'percent_encoding_count',
    'has_encoded_chars',
    'suspicious_file_extension',
    'suspicious_keyword_count',
    'keyword_in_domain',
    'keyword_in_path',
    'has_leetspeak_substitution',
    'min_brand_edit_distance',
    'is_brand_typo',
    'brand_in_subdomain_or_path',
    'suspicious_hyphen_brand',
    'vowel_consonant_ratio'
]

# Backward-compatibility alias
FEATURE_NAMES_V2 = FEATURE_NAMES


def calculate_shannon_entropy(s: str) -> float:
    """
    Calculate the Shannon entropy of a string representing character randomness.
    Higher entropy indicates obfuscation, hex/base64 strings, or algorithmically generated domains.
    """
    if not s:
        return 0.0
    counts = collections.Counter(s)
    total = len(s)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def fast_levenshtein_distance(s1: str, s2: str) -> int:
    """
    Compute Levenshtein edit distance between two strings with linear memory.
    """
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (0 if c1 == c2 else 1)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract all 41 lexical, structural, and brand-impersonation features
    directly from a raw URL string without any network contact.
    """
    u = str(url or '').strip()
    u_len = len(u)
    u_lower = u.lower()

    # 1. url_length
    url_length = u_len

    # 2. dot_count
    dot_count = u.count('.')

    # 3. https_flag & suspicious_scheme
    has_scheme = '://' in u
    if has_scheme:
        scheme = u.split('://')[0].lower()
        https_flag = 1 if scheme == 'https' else 0
        suspicious_scheme = 0 if scheme in ('http', 'https') else 1
    else:
        https_flag = 1 if u_lower.startswith('https') else 0
        suspicious_scheme = 0

    # 4. digit_count & percentage_numeric_chars
    digit_count = sum(c.isdigit() for c in u)
    percentage_numeric_chars = (digit_count / u_len * 100.0) if u_len > 0 else 0.0

    # 5. hyphen_count
    hyphen_count = u.count('-')

    # 6. special_char_count & at_symbol_count
    special_char_count = sum(1 for c in u if c in SPECIAL_CHARS)
    at_symbol_count = u.count('@')

    # 7. percent_encoding_count & has_encoded_chars
    percent_encoding_count = u.count('%')
    has_encoded_chars = 1 if percent_encoding_count > 0 else 0

    # 8. url_entropy
    url_entropy = calculate_shannon_entropy(u)

    # Parse components safely
    parsed = urllib.parse.urlparse(u if u.startswith(('http://', 'https://')) else 'http://' + u)
    raw_host = parsed.netloc.split(':')[0]
    host = raw_host.lower()
    hostname_length = len(host)

    # 9. consecutive_char_repeat_max & has_repeated_char_run
    # Computed on alphanumeric host characters to detect typo-squatting runs (e.g. 'gooogle', 'youtubee', 'faceboook')
    host_clean = re.sub(r'[^a-zA-Z0-9]', '', host) if host else ''
    char_runs = [len(m[0]) for m in re.findall(r'((.)\2*)', host_clean)] if host_clean else [0]
    consecutive_char_repeat_max = max(char_runs) if char_runs else 0
    # Any run of 3 or more identical characters in URL (alphanumeric)
    url_alpha_runs = [len(m[0]) for m in re.findall(r'(([a-zA-Z0-9])\2{2,})', u)]
    has_repeated_char_run = 1 if url_alpha_runs else 0

    # 10. suspicious_separator_count (e.g. '--', '__', '::')
    suspicious_separator_count = len(re.findall(r'--|__|\.\.|::', u))

    # 11. has_ip_address
    has_ip_address = 1 if IP_REGEX.match(host) else 0

    # Domain, SLD, Subdomains, TLD breakdown
    parts = host.split('.')
    if len(parts) >= 2 and not has_ip_address:
        tld = parts[-1]
        domain_name = parts[-2]
        subdomain_parts = parts[:-2]
        subdomain_count = len(subdomain_parts)
        has_hyphen_in_domain = 1 if any('-' in p for p in parts) else 0
    elif has_ip_address:
        tld = ''
        domain_name = host
        subdomain_parts = []
        subdomain_count = 0
        has_hyphen_in_domain = 0
    else:
        tld = ''
        domain_name = host
        subdomain_parts = []
        subdomain_count = 0
        has_hyphen_in_domain = 1 if '-' in host else 0

    domain_name_length = len(domain_name)
    tld_length = len(tld)
    tld_popularity = 1 if tld in POPULAR_TLDS else 0

    # 12. Entropies for domain and hostname
    domain_entropy = calculate_shannon_entropy(domain_name)
    hostname_entropy = calculate_shannon_entropy(host)

    # 13. Subdomain structure & unusual patterns
    subdomain_str = '.'.join(subdomain_parts)
    suspicious_subdomain_structure = 1 if (
        subdomain_count > 2 or
        any(c.isdigit() for c in subdomain_str) or
        any('-' in p for p in subdomain_parts)
    ) else 0

    unusual_domain_patterns = 1 if (
        domain_name.startswith('-') or
        domain_name.endswith('-') or
        '--' in domain_name
    ) else 0

    # 14. Path, Query, Fragment metrics
    path = parsed.path
    path_length = len(path)
    path_segments = [p for p in path.split('/') if p]
    path_segment_count = len(path_segments)

    query = parsed.query
    query_length = len(query)
    query_param_count = len(query.split('&')) if query else 0

    fragment_length = len(parsed.fragment)

    # 15. Suspicious file extension
    path_lower = path.lower()
    suspicious_file_extension = 1 if any(
        path_lower.endswith(ext) or (ext + '/') in path_lower for ext in SUSPICIOUS_EXTENSIONS
    ) else 0

    # 16. Content-independent keyword features
    domain_tokens = set(re.split(r'[-._]', host))
    path_tokens = set(re.split(r'[/._?=&-]', path_lower + '?' + query.lower()))

    keyword_in_domain = 1 if any(kw in domain_tokens or kw in host for kw in SUSPICIOUS_KEYWORDS) else 0
    keyword_in_path = 1 if any(kw in path_tokens for kw in SUSPICIOUS_KEYWORDS) else 0
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in u_lower)

    # 17. Typo-Squatting & Impersonation Representation
    has_leetspeak_substitution = 1 if bool(LEETSPEAK_REGEX.search(domain_name)) else 0

    # Brand similarity: Compute minimum edit distance to reference brands
    l_sld = len(domain_name)
    # Only test brands with reasonable length difference for performance
    candidate_brands = [b for b in REFERENCE_BRANDS if abs(len(b) - l_sld) <= 3]
    if candidate_brands:
        distances = [fast_levenshtein_distance(domain_name, b) for b in candidate_brands]
        min_brand_edit_distance = min(distances)
    else:
        min_brand_edit_distance = 6

    # Cap edit distance at 6 for numeric stability
    min_brand_edit_distance = min(min_brand_edit_distance, 6)

    # Typo flag: 1- or 2-character mutation of a brand, but not the exact legitimate brand
    is_brand_typo = 1 if (min_brand_edit_distance in (1, 2) and domain_name not in REFERENCE_BRANDS) else 0

    # Brand embedded in subdomain, path, or compound host (e.g. microsoft-login.xyz, paypal.com.update.net)
    brand_in_subdomain_or_path = 1 if any(
        (b in host and b != domain_name) or (b in path_tokens and b != domain_name)
        for b in REFERENCE_BRANDS
    ) else 0

    # Brand adjacent to a hyphen in host (e.g. microsoft-login, paypal-verify)
    suspicious_hyphen_brand = 1 if any(
        (f"{b}-" in host or f"-{b}" in host) for b in REFERENCE_BRANDS
    ) else 0

    # Vowel to consonant ratio in domain name
    vowels = sum(1 for c in domain_name if c in 'aeiou')
    consonants = sum(1 for c in domain_name if c.isalpha() and c not in 'aeiou')
    vowel_consonant_ratio = round((vowels / (consonants + 1e-5)), 4)

    return {
        'url_length': url_length,
        'hostname_length': hostname_length,
        'path_length': path_length,
        'query_length': query_length,
        'fragment_length': fragment_length,
        'dot_count': dot_count,
        'subdomain_count': subdomain_count,
        'path_segment_count': path_segment_count,
        'query_param_count': query_param_count,
        'digit_count': digit_count,
        'percentage_numeric_chars': round(percentage_numeric_chars, 6),
        'hyphen_count': hyphen_count,
        'has_hyphen_in_domain': has_hyphen_in_domain,
        'special_char_count': special_char_count,
        'at_symbol_count': at_symbol_count,
        'suspicious_separator_count': suspicious_separator_count,
        'consecutive_char_repeat_max': consecutive_char_repeat_max,
        'has_repeated_char_run': has_repeated_char_run,
        'domain_name_length': domain_name_length,
        'domain_entropy': round(domain_entropy, 6),
        'hostname_entropy': round(hostname_entropy, 6),
        'url_entropy': round(url_entropy, 6),
        'suspicious_subdomain_structure': suspicious_subdomain_structure,
        'unusual_domain_patterns': unusual_domain_patterns,
        'has_ip_address': has_ip_address,
        'tld_length': tld_length,
        'tld_popularity': tld_popularity,
        'https_flag': https_flag,
        'suspicious_scheme': suspicious_scheme,
        'percent_encoding_count': percent_encoding_count,
        'has_encoded_chars': has_encoded_chars,
        'suspicious_file_extension': suspicious_file_extension,
        'suspicious_keyword_count': suspicious_keyword_count,
        'keyword_in_domain': keyword_in_domain,
        'keyword_in_path': keyword_in_path,
        'has_leetspeak_substitution': has_leetspeak_substitution,
        'min_brand_edit_distance': min_brand_edit_distance,
        'is_brand_typo': is_brand_typo,
        'brand_in_subdomain_or_path': brand_in_subdomain_or_path,
        'suspicious_hyphen_brand': suspicious_hyphen_brand,
        'vowel_consonant_ratio': vowel_consonant_ratio
    }


# Backward-compatibility alias
extract_url_features_v2 = extract_url_features


def extract_feature_vector(url: str, feature_names: List[str] = None) -> List[float]:
    """
    Extract all 41 features and return an ordered numerical list.
    """
    if feature_names is None:
        feature_names = FEATURE_NAMES
    features_dict = extract_url_features(url)
    return [features_dict[name] for name in feature_names]


# Backward-compatibility alias
extract_feature_vector_v2 = extract_feature_vector
