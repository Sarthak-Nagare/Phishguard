"""
PhishGuard — Reusable URL Phishing Predictor
Loads the trained machine-learning model (HistGradientBoosting on LegitPhish with balanced augmentation)
and performs live heuristic phishing predictions.

Key capabilities:
1. Accepts raw or normalized URL strings.
2. Extracts 41 advanced lexical, structural, and brand-impersonation features via feature_extractor.py.
3. Computes estimated class probabilities and prediction verdicts.
4. Returns structured results including extracted URL characteristics.
"""

import os
import joblib
from typing import Dict, Any, Optional
import pandas as pd

import feature_extractor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Active Production Model: HistGradientBoosting with balanced data augmentation
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'phishguard_model.joblib')

# Module-level cached model artifact to prevent re-reading disk on every prediction
_CACHED_ARTIFACT: Optional[Dict[str, Any]] = None


def load_model_artifact(model_path: str = MODEL_PATH) -> Dict[str, Any]:
    """
    Load the trained model artifact package from disk with caching.
    """
    global _CACHED_ARTIFACT
    if _CACHED_ARTIFACT is None or getattr(load_model_artifact, '_loaded_path', None) != model_path:
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model artifact not found at '{model_path}'. "
                f"Please ensure models/phishguard_model.joblib is present."
            )
        _CACHED_ARTIFACT = joblib.load(model_path)
        load_model_artifact._loaded_path = model_path
    return _CACHED_ARTIFACT


def predict_url(url: str, model_path: str = MODEL_PATH) -> Dict[str, Any]:
    """
    Predict whether a given URL is Phishing or Legitimate using the trained machine-learning model.
    
    Parameters:
        url: Raw or normalized URL string to inspect
        model_path: Optional path to saved joblib model artifact (defaults to phishguard_model.joblib)
        
    Returns:
        Dictionary containing:
        - 'url': The evaluated URL string
        - 'prediction': 'Phishing' or 'Legitimate'
        - 'confidence': Statistical confidence estimate (0.0 to 1.0)
        - 'confidence_percentage': Human-readable percentage string
        - 'probabilities': Dict with 'phishing' and 'legitimate' estimated probabilities
        - 'features': Dict of extracted URL characteristics
        - 'model_used': Formatted display name (e.g. 'HistGradientBoosting')
        - 'model_version': Active model version identifier
        - 'model_name': Base algorithm name ('HistGradientBoosting')
        - 'feature_count': Total number of features evaluated
        - 'status': 'success'
        - 'disclaimer': Statistical estimate notice
        
    Security note:
        Operates entirely on passive string heuristics; never initiates network connections.
    """
    cleaned_url = str(url or '').strip()
    if not cleaned_url:
        raise ValueError("URL cannot be empty or blank.")

    artifact = load_model_artifact(model_path)
    model = artifact['model']
    scaler = artifact.get('scaler')
    use_scaled = artifact.get('use_scaled', False)
    feature_names = artifact['feature_names']
    model_version = artifact.get('model_version', '1.0')
    raw_model_name = artifact.get('model_name', 'HistGradientBoosting')
    display_model_name = raw_model_name

    # Extract 41 features using feature_extractor
    features_dict = feature_extractor.extract_url_features(cleaned_url)
    feature_vector = [features_dict[name] for name in feature_names]

    # Convert to DataFrame to maintain exact feature names and column ordering
    input_df = pd.DataFrame([feature_vector], columns=feature_names)

    if use_scaled and scaler is not None:
        input_data = scaler.transform(input_df)
    else:
        input_data = input_df

    # Predict class probabilities
    probabilities = model.predict_proba(input_data)[0]
    classes = list(model.classes_)

    p_phishing = float(probabilities[classes.index(0)]) if 0 in classes else 0.0
    p_legitimate = float(probabilities[classes.index(1)]) if 1 in classes else 0.0

    # Determine final prediction and estimated confidence
    if p_phishing >= p_legitimate:
        prediction = 'Phishing'
        confidence = p_phishing
    else:
        prediction = 'Legitimate'
        confidence = p_legitimate

    return {
        'url': cleaned_url,
        'prediction': prediction,
        'confidence': round(confidence, 4),
        'confidence_percentage': f"{confidence * 100:.1f}%",
        'probabilities': {
            'phishing': round(p_phishing, 4),
            'legitimate': round(p_legitimate, 4)
        },
        'features': features_dict,
        'model_used': display_model_name,
        'model_version': model_version,
        'model_name': raw_model_name,
        'feature_count': len(feature_names),
        'status': 'success',
        'disclaimer': (
            "Confidence is an estimated statistical probability based on lexical and "
            "structural URL characteristics. It does not represent a live guarantee."
        )
    }

