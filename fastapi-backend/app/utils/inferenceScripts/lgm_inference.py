import pandas as pd
import numpy as np
import joblib
from feature_extraction import extract_features_enhanced
from typoSquattingFunction import apply_typosquatting_heuristic 

artifact = joblib.load('/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/fastapi-backend/models/716k typosquatting/lgbm classifier v_3.pkl')
model = artifact['model']
features = artifact['feature_names']

def process_url_with_heuristic_lightgbm(url):
  
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    X_dict = extract_features_enhanced(url)
    X = pd.DataFrame([X_dict])

    for col in features:
        if col not in X.columns:
            X[col] = 0
    X = X[features]

    model_pred = model.predict(X)[0]
    model_proba = model.predict_proba(X)[0]
    classes = model.classes_
    prob_dict = dict(zip(classes, model_proba))

    final_pred, final_proba, reason = apply_typosquatting_heuristic(
        url, model_pred, prob_dict
    )

    return {
        'url': url,
        'model_prediction': model_pred,
        'model_probabilities': prob_dict,
        'final_prediction': final_pred,
        'final_probabilities': final_proba,
        'detection_reason': reason,
        'heuristic_applied': reason != "model_decision"
    }

