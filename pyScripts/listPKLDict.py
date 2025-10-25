import joblib
import pprint

# ===== Load the .pkl dictionary =====
pkl_path = "/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/fastapi_backend/models/716k typosquatting/lgbm classifier v_3.pkl"  # change path if needed
data = joblib.load(pkl_path)

print("\n=== BASIC INFO ===")
print("Type:", type(data))
print("Top-level keys:", list(data.keys()))

print("\n=== DETAILED CONTENTS ===")
pprint.pprint(data)  # shows full structure (truncated for large data)

# ===== Extract known elements safely =====
model = data.get("model", None)
metadata = data.get("metadata", None)
feature_names = data.get("feature_names", None)

print("\n=== ELEMENT DETAILS ===")
if model is not None:
    print("Model type:", type(model))
    # Try to get feature names from model if not separately stored
    try:
        model_feature_names = model.feature_name()
        print("Model reports", len(model_feature_names), "features.")
    except Exception as e:
        print("Could not read features from model:", e)
else:
    print("No model found in dict.")

if metadata is not None:
    print("\nMetadata keys:", list(metadata.keys()))
else:
    print("\nNo metadata found.")

if feature_names is not None:
    print("\nFeature list length:", len(feature_names))
    print("First few feature names:", feature_names[:10])
else:
    print("\nNo separate feature_names list found.")

# ===== Optional: Save a text dump for full inspection =====
dump_path = "model_dict_dump.txt"
with open(dump_path, "w") as f:
    for k, v in data.items():
        f.write(f"\n===== {k} =====\n")
        f.write(str(v))
        f.write("\n")

print(f"\nFull dump saved to: {dump_path}")

