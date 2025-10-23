import joblib
from pathlib import Path

MODELS_DIR = Path(__file__).resolve().parents[2] / "models" / "716k typosquatting"

rf = joblib.load(MODELS_DIR / "rf classifier v_3.pkl")
xgb = joblib.load(MODELS_DIR / "xgboost classifier v_3.pkl")
lgb = joblib.load(MODELS_DIR / "lgbm classifier v_3.pkl")

def predict_ensemble(features: list[float]):
    preds = [
        rf.predict_proba([features])[0][1],
        xgb.predict_proba([features])[0][1],
        lgb.predict_proba([features])[0][1],
    ]
    conf = sum(preds) / len(preds)
    return conf > 0.7, conf, "ensemble_RF_XGB_LGBM"
