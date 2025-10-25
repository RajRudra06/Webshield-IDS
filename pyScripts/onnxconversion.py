import joblib
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

# ===== Load dict =====
data = joblib.load("/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/fastapi_backend/models/716k typosquatting/lgbm classifier v_3.pkl")

# Extract LightGBM classifier and feature info
lgbm_clf = data["model"]
feature_names = data["feature_names"]
n_features = len(feature_names)

print("Loaded model:", type(lgbm_clf))
print("Number of features:", n_features)

# ===== Extract the Booster (onnxmltools needs this) =====
booster = lgbm_clf.booster_

# ===== Convert to ONNX =====
initial_type = [('input', FloatTensorType([None, n_features]))]
onnx_model = onnxmltools.convert_lightgbm(booster, initial_types=initial_type)

# ===== Save to file =====
with open("LightGBM version.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("ONNX export complete → model.onnx")
