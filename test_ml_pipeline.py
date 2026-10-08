"""
PhishGuard — Machine Learning Pipeline Test Suite
Tests feature extraction, model loading, and prediction functions.
"""

import os
import predictor
import feature_extractor

# 1. Feature Extraction Tests (41 Features)
print("\n--- Test 1: Feature Extraction Integrity (41 Features) ---")
url = "https://keraekken-loagginnusa.godaddysites.com/test?param=1"
feats = feature_extractor.extract_url_features(url)
assert len(feats) == 41, f"Expected 41 features, got {len(feats)}"
assert all(k in feats for k in feature_extractor.FEATURE_NAMES), "Missing feature keys"
assert feats['https_flag'] == 1
assert feats['has_hyphen_in_domain'] == 1
assert feats['url_length'] == len(url)
vec = feature_extractor.extract_feature_vector(url)
assert len(vec) == 41
print("Pass: All 41 features extracted cleanly directly from raw URL string.")

# 2. Model Artifact Verification
print("\n--- Test 2: Model Artifact Verification ---")
assert os.path.exists(predictor.MODEL_PATH), f"Model file missing at {predictor.MODEL_PATH}"
artifact = predictor.load_model_artifact()
assert 'model' in artifact
assert 'scaler' in artifact
assert 'feature_names' in artifact
assert len(artifact['feature_names']) == 41
assert artifact['label_mapping'] == {0: 'Phishing', 1: 'Legitimate'}
assert 'model_version' in artifact
print(f"Pass: Model artifact successfully loaded ({artifact['model_name']}).")

# 3. Predictor Output Structure Verification
print("\n--- Test 3: Predictor Output Contract ---")
res = predictor.predict_url("https://en.wikipedia.org/wiki/Computer_security")
assert res['status'] == 'success'
assert res['prediction'] in ['Phishing', 'Legitimate']
assert 0.0 <= res['confidence'] <= 1.0
assert 'confidence_percentage' in res
assert 'probabilities' in res
assert 'phishing' in res['probabilities']
assert 'legitimate' in res['probabilities']
assert abs(res['probabilities']['phishing'] + res['probabilities']['legitimate'] - 1.0) < 1e-3
assert len(res['features']) == 41, f"Expected 41 features, got {len(res['features'])}"
assert 'model_version' in res
assert res['model_name'] == 'HistGradientBoosting'
assert 'disclaimer' in res
print(f"Pass: Predictor output contract verified. Sample verdict: {res['prediction']} ({res['confidence_percentage']}) with 41 features.")

# 4. Error Handling
print("\n--- Test 4: Error Handling on Invalid/Blank Input ---")
try:
    predictor.predict_url("")
    assert False, "Should have raised ValueError on empty string"
except ValueError:
    print("Pass: Blank URL rejected with ValueError.")

print("\n=======================================================")
print("ALL ML PIPELINE UNIT TESTS PASSED! [100%]")
print("=======================================================\n")
