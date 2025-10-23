import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import LabelEncoder
from feature_utils import extract_features_enhanced
from typosquattingHeuristicTestLightGBM import apply_typosquatting_heuristic 

artifact_path = "/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/ai-systems/results and model files/XGBOOST Results 716k typosquatting /xgboost_url_classifier_v1.0.0.pkl"
artifact = joblib.load(artifact_path)
model = artifact['model']
features = artifact['feature_names']

encoder_path = "/content/drive/MyDrive/Webshield Dataset/XGBOOST Results 716k typosquatting/xgb_label_encoder.pkl"
try:
    le = joblib.load(encoder_path)
except:
    le = LabelEncoder()
    le.classes_ = np.array(['benign', 'defacement', 'malware', 'phishing'])


# ============================================================
# SINGLE URL PREDICTION + HEURISTIC LAYER
# ============================================================

def process_url_with_heuristic_xgboost(url):
    """
    Run XGBoost model prediction + heuristic correction
    for a single URL.
    """

    # ---------- Step 1: Add scheme if missing ----------
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # ---------- Step 2: Feature extraction ----------
    X_dict = extract_features_enhanced(url)
    X = pd.DataFrame([X_dict])

    # Align with training features
    for col in features:
        if col not in X.columns:
            X[col] = 0
    X = X[features]

    # ---------- Step 3: Model prediction ----------
    proba = model.predict_proba(X)[0]             # probabilities (array)
    pred_numeric = int(np.argmax(proba))          # numeric label
    model_pred = le.inverse_transform([pred_numeric])[0]  # string label

    # ---------- Step 4: Convert to dict (for heuristic layer) ----------
    prob_dict = {le.classes_[i]: round(float(proba[i]), 4)
                 for i in range(len(le.classes_))}

    # ---------- Step 5: Apply heuristic layer ----------
    final_pred, final_proba, reason = apply_typosquatting_heuristic(
        url, model_pred, prob_dict
    )

    # ---------- Step 6: Return unified output ----------
    return {
        'url': url,
        'model_prediction': model_pred,
        'model_probabilities': prob_dict,
        'final_prediction': final_pred,
        'final_probabilities': final_proba,
        'detection_reason': reason,
        'heuristic_applied': reason != "model_decision"
    }


# ============================================================
# EXAMPLE USAGE
# ============================================================

if __name__ == "__main__":
    test_urls = [
        "www.g00gle.com",
        "www.paypai.com",
        "https://www.facebook.com",
        "https://secure-amazon-login.ga","https://www.gaeboy.com", "www.google.tk..https.com", "www.facebook.com", "www.youtube.com", "www.twitter.com", "www.instagram.com", "www.wikipedia.org", "www.amazon.com", "www.netflix.com", "www.linkedin.com", "https://www.google.com", "https://www.facebook129.232.23.com", "https://www.amazon.com", "https://www.microsoft.com", "https://www.apple.com", "https://www.github.com", "https://www.stackoverflow.com", "https://www.reddit.com", "https://www.flipkart.com", "https://www.paytm.com", "https://www.icicibank.com", "https://www.hdfcbank.com", "https://www.swiggy.com", "https://www.zomato.com", "https://www.google-login.tk", "https://www.paypal-secure.ml", "https://www.amazon-verify.ga", "https://www.facebook-recovery.cf", "https://secure-netflix-account.xyz", "https://www.apple-id-locked.top", "https://www.paypal.com.verify-account.com", "https://www.amazon.com-login.net", "https://secure-google.com", "https://www.facebook-help.com", "https://www.goog1e.com", "https://www.faceb00k.com", "https://www.microoft.com", "https://www.arnazon.com", "https://login-google.com", "https://accounts-google-secure.test", "https://google-secure-login.test", "https://paypal-secure-login.test", "https://secure-paypal-update.test", "https://signin-amazon.test", "https://amazon-secure-update.test", "https://appleid-recovery.test", "https://appleid-security.test", "https://netflix-support.test", "https://facebook-account-secure.test", "https://linkedin-security.test", "https://github-login.test", "https://microsoft-account.verify.test", "https://support-google.com.scam", "https://google.payments.verify.test", "https://paypai.com", "https://amzon-payments.com", "https://face-book-login.org", "http://update-paypal.info", "http://secure-paypal-login.info", "https://verify-paytm.secure.test", "https://icici-bank-login.test", "https://hdfc-bank-verify.test", "https://swiggy-support-login.test", "https://zomato-account-verify.test", "https://accounts.google.security-alert.test", "https://apple-support-login.test", "https://microsoft-update-account.test", "https://paypal-account-recovery.test", "https://amazon-billing-alert.test", "https://netflix-payment-issue.test", "https://facebook-verify-now.test", "https://linkedin-verify-account.test", "https://github-2fa-setup.test", "https://stackoverflow-login.test", "https://reddit-security-alert.test", "https://flipkart-payment-verify.test", "https://paytm-verify-now.test", "https://secure-icicibank-login.test", "https://hdfc-verify-account.test", "https://delivery-swiggy.verify.test", "https://zomato-verify-payment.test", "https://www-google-login.example", "https://paypal-confirm.example", "https://amazon-secure.example", "https://facebook-restore.example", "https://netflix-verify.example", "https://apple-account.example", "https://google-support.example", "https://paypal-support.example", "https://amazon-support.example", "https://facebook-support.example", "https://netflix-support.example", "https://phish-google.test", "https://phish-paypal.test", "https://phish-amazon.test", "https://secure-login-google.co", "https://secure-login-paypal.co", "https://login-amazon-secure.co", "http://verify-google-login.org", "http://verify-paypal-login.org", "http://verify-amazon-login.org"
    ]

    results = []
    for url in test_urls:
        result = process_url_with_heuristic_xgboost(url)
        results.append(result)
        print("\nURL:", result['url'])
        print("Model Prediction:", result['model_prediction'])
        print("Model Probabilities:", result['model_probabilities'])
        print("Final Prediction (after heuristic):", result['final_prediction'])
        print("Final Probabilities:", result['final_probabilities'])
        print("Detection Reason:", result['detection_reason'])

    # Optional: save all results to CSV
    df_results = pd.DataFrame(results)
    df_results.to_csv("xgboost_heuristic_predictions.csv", index=False)
    print("\n✅ Predictions saved to: xgboost_heuristic_predictions.csv")

