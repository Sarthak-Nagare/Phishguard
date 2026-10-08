# PhishGuard — Machine Learning Phishing URL Detection

PhishGuard is an intelligent cybersecurity web application that detects phishing URLs using passive, heuristic feature extraction and trained machine-learning classification.

By extracting **41 structural, lexical, and brand-impersonation features** directly from URL strings, PhishGuard estimates the statistical likelihood that a target address is deceptive or malicious—without ever connecting to, fetching content from, or executing code on the destination server.

---

## Key Features

- **Proactive Offline URL Inspection**: Rapid feature evaluation performed purely via lexical and structural analysis without initiating network connections or DNS queries.
- **Machine-Learning Classification**: Uses a trained gradient-boosted decision tree classifier (`HistGradientBoostingClassifier`) optimized for both in-distribution and out-of-distribution typo-squatting detection.
- **Brand Impersonation & Typosquatting Defense**: Heuristic detection of Levenshtein edit distances against high-profile target brands, leetspeak digit substitutions, and combosquatting (brand + security keywords).
- **User Authentication & Session Management**: Secure user registration and login protected with modern salted password hashing (`scrypt`) and session cookie hardening.
- **Personalized Scan Dashboard**: Authenticated users can view their recent URL scan history, personal threat detection statistics, and breakdown of extracted link characteristics.
- **In-Memory Rate Limiting**: Built-in sliding-window rate limiting to defend authentication and scan endpoints from brute-force automated abuse.
- **Modern Responsive Interface**: Clean, dark-themed UI built with semantic HTML and custom CSS, optimized for mobile, tablet, and desktop viewports.

---

## Technology Stack

- **Backend**: Python 3.13, Flask 3.1
- **Machine Learning**: scikit-learn, joblib, pandas, NumPy
- **Frontend**: Vanilla HTML5, Vanilla CSS3, Vanilla JavaScript (zero external UI dependencies)
- **Database**:
  - **Local Development**: SQLite (`phishguard.db`, automatically initialized on startup)
  - **Production Deployment**: PostgreSQL (configured separately during deployment)
- **Security & Cryptography**: Werkzeug `scrypt` password hashing, Python standard library `secrets`

---

## Machine Learning Approach

PhishGuard evaluates URLs through a supervised classification pipeline:

1. **Passive Feature Extraction**: URLs are parsed and evaluated to generate a 41-dimensional numerical feature vector.
2. **Balanced Training Augmentation**: The model was trained on the benchmark LegitPhish dataset (100,871 samples) augmented with balanced synthetic permutations (typos, omissions, substitutions, combosquatting, and exact brand root domains) applied strictly to the training partition to avoid data leakage.
3. **Statistical Inference**: The serialized model (`models/phishguard_model.joblib`) predicts class probabilities (`Phishing` vs. `Legitimate`) and assigns a confidence percentage.

### 41 Extracted URL Features

| Category | Features Included |
|---|---|
| **1. Basic URL Structure** | `url_length`, `hostname_length`, `path_length`, `query_length`, `fragment_length`, `dot_count`, `subdomain_count`, `path_segment_count`, `query_param_count` |
| **2. Character Obfuscation** | `digit_count`, `percentage_numeric_chars`, `hyphen_count`, `has_hyphen_in_domain`, `special_char_count`, `at_symbol_count`, `suspicious_separator_count`, `consecutive_char_repeat_max`, `has_repeated_char_run` |
| **3. Domain Characteristics** | `domain_name_length`, `domain_entropy`, `hostname_entropy`, `url_entropy`, `suspicious_subdomain_structure`, `unusual_domain_patterns`, `has_ip_address`, `tld_length`, `tld_popularity` |
| **4. Security & Protocol** | `https_flag`, `suspicious_scheme`, `percent_encoding_count`, `has_encoded_chars`, `suspicious_file_extension` |
| **5. Lexical Keywords** | `suspicious_keyword_count`, `keyword_in_domain`, `keyword_in_path` |
| **6. Impersonation & Typos** | `has_leetspeak_substitution`, `min_brand_edit_distance`, `is_brand_typo`, `brand_in_subdomain_or_path`, `suspicious_hyphen_brand`, `vowel_consonant_ratio` |

---

## Project Architecture

```
├── app.py                     # Main Flask application and HTTP route handlers
├── database.py                # Database connection and data access layer (SQLite local)
├── scanner.py                 # URL normalization, structural validation, and scan controller
├── predictor.py               # ML model loader and live inference pipeline
├── feature_extractor.py       # 41-feature lexical and structural extractor
├── train_model.py             # Model training and data augmentation pipeline
│
├── models/
│   ├── phishguard_model.joblib # Serialized production machine-learning model
│   └── model_metadata.json    # Architecture metadata, hyperparameters, and feature list
│
├── data/
│   └── dataset_features_v2.csv # Base pre-extracted 41-feature training dataset
│
├── templates/                 # Jinja2 HTML templates
│   ├── index.html             # Public landing page
│   ├── register.html          # User account registration
│   ├── login.html             # User authentication
│   ├── dashboard.html         # User metrics and scan history
│   └── scan.html              # URL scanning interface
│
├── static/                    # Frontend styling and scripts
│   ├── style.css              # Unified design system stylesheet
│   ├── script.js              # Landing page navigation interactions
│   ├── register.js            # Client-side registration form validation
│   └── login.js               # Client-side login form handling
│
├── test_scanner.py            # URL validation and scanner integration tests
├── test_feature_extractor.py  # 41-feature extraction unit tests
├── test_ml_pipeline.py        # ML predictor and output contract tests
├── test_registration.py       # User registration test suite
├── test_login.py              # User authentication test suite
├── test_dashboard.py          # Dashboard metrics and data isolation tests
│
├── requirements.txt           # Python dependency specifications
├── .env.example               # Environment variable configuration template
└── .gitignore                 # Version control exclusions
```

---

## Local Setup & Installation

### 1. Prerequisites
- Python 3.10+ (Python 3.13 recommended)
- `pip` package manager

### 2. Clone the Repository
```bash
git clone https://github.com/your-username/phishguard.git
cd phishguard
```

### 3. Create and Activate a Virtual Environment
```bash
# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate

# On Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables
Copy `.env.example` to `.env` (or set environment variables in your shell):
```bash
cp .env.example .env
```
For local development, sensible defaults will be used automatically if `.env` is omitted.

---

## Running the Application

To launch the local development server:

```bash
python app.py
```

The application will start locally at:
- **Landing Page**: `http://127.0.0.1:5000/`
- **Register**: `http://127.0.0.1:5000/register`
- **Login**: `http://127.0.0.1:5000/login`
- **Scanner**: `http://127.0.0.1:5000/scan` (requires authentication)
- **Dashboard**: `http://127.0.0.1:5000/dashboard` (requires authentication)

---

## Running Automated Tests

Run the unit and integration test suites:

```bash
# Test the URL feature extractor (41 features)
python -m unittest test_feature_extractor.py

# Test the ML predictor pipeline
python test_ml_pipeline.py

# Test URL scanner and HTTP routes
python -m unittest test_scanner.py

# Test authentication and registration
python test_registration.py
python test_login.py

# Test dashboard and data isolation
python test_dashboard.py
```

---

## Model Training & Reproduction

The pre-trained model artifact (`models/phishguard_model.joblib`) is included in the repository. If you wish to retrain the model from scratch:

```bash
python train_model.py
```

This script will:
1. Load `data/dataset_features_v2.csv`.
2. Perform an untouched 80/20 train/test split (seed=42).
3. Generate balanced synthetic phishing and legitimate domain variations strictly from the training split.
4. Benchmark Logistic Regression, Random Forest, and HistGradientBoosting classifiers.
5. Export the winning model artifact to `models/phishguard_model.joblib` and benchmark metrics to `model_comparison.csv`.

---

## Database Architecture

- **Local Development**: PhishGuard uses SQLite (`phishguard.db`). Tables (`users`, `scan_history`) and indexes are created automatically on application startup via `database.init_db()`.
- **Production Deployment**: A production-grade relational database such as PostgreSQL will be configured separately during deployment. Database access functions are centralized in `database.py` to facilitate straightforward environment-based connection adaptation.

---

## Security & Privacy Considerations

- **Zero Remote Execution**: PhishGuard never visits, pings, or downloads content from submitted target URLs.
- **Password Security**: Passwords are never stored in plaintext. They are hashed using Werkzeug's secure `scrypt` implementation.
- **Data Isolation**: Scan records and history queries are strictly filtered by authenticated user ID.
- **Rate Limiting**: Sliding-window rate limiters prevent brute-force attacks on sensitive endpoints.
- **Defensive HTTP Headers**: Responses automatically include `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, and `Referrer-Policy`.

---

## Known Limitations

1. **Statistical Heuristic Estimation**: PhishGuard provides statistical probability assessments based on lexical patterns; it does not guarantee 100% detection of unknown or novel threats.
2. **Passive vs. Dynamic Analysis**: Because PhishGuard operates purely on URL strings to maintain user safety, it does not inspect webpage content, SSL certificates, or runtime JavaScript behavior.
3. **Reference Brand Stems**: Typo detection evaluates Levenshtein distance against known high-profile brand stems; novel brands not covered by reference stems rely on general lexical and structural features.
