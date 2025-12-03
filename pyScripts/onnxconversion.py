# # import joblib
# # import onnxmltools
# # from onnxmltools.convert.common.data_types import FloatTensorType

# # # ===== Load dict =====
# # data = joblib.load("/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/fastapi_backend/models/716k typosquatting/lgbm classifier v_3.pkl")

# # # Extract LightGBM classifier and feature info
# # lgbm_clf = data["model"]
# # feature_names = data["feature_names"]
# # n_features = len(feature_names)

# # print("Loaded model:", type(lgbm_clf))
# # print("Number of features:", n_features)

# # # ===== Extract the Booster (onnxmltools needs this) =====
# # booster = lgbm_clf.booster_

# # # ===== Convert to ONNX =====
# # initial_type = [('input', FloatTensorType([None, n_features]))]
# # onnx_model = onnxmltools.convert_lightgbm(booster, initial_types=initial_type)

# # # ===== Save to file =====
# # with open("LightGBM version.onnx", "wb") as f:
# #     f.write(onnx_model.SerializeToString())

# # print("ONNX export complete → model.onnx")









import pickle
import onnx
from onnxmltools.convert import convert_lightgbm
from skl2onnx.common.data_types import FloatTensorType

# Step 1: Load your LightGBM model
print("Loading LightGBM model...")
with open('/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/fastapi_backend/models/716k typosquatting/lgbm classifier v_3.pkl', 'rb') as f:  # ← Change 'your_model.pkl' to your actual file name
    lgbm_model = pickle.load(f)

print("Model loaded successfully!")
print(f"Model type: {type(lgbm_model)}")

# Step 2: Define input shape
# You have 66 features, so input shape is [batch_size, 66]
initial_type = [('input', FloatTensorType([None, 66]))]

# Step 3: Convert to ONNX with correct options
print("Converting to ONNX...")
onnx_model = convert_lightgbm(
    lgbm_model,
    initial_types=initial_type,
    target_opset=12,  # Compatible with ONNX Runtime Web
    options={
        'zipmap': False,  # ← CRITICAL: Makes probabilities a tensor instead of map
        'nocl': True       # ← Ensures output is probabilities, not class labels only
    }
)

# Step 4: Save the ONNX model
output_path = 'lightGBMClassifier_fixed.onnx'
print(f"Saving ONNX model to {output_path}...")
onnx.save_model(onnx_model, output_path)

print("✅ Conversion complete!")

# Step 5: Verify the model
print("\n📊 Model verification:")
print(f"  Inputs: {[inp.name for inp in onnx_model.graph.input]}")
print(f"  Outputs: {[out.name for out in onnx_model.graph.output]}")

# Check output types
for output in onnx_model.graph.output:
    print(f"  Output '{output.name}' type: {output.type}")