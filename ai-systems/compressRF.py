import joblib

# Path to your existing model
input_path = "/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/fastapi-backend/models/716k typosquatting/rf classifier v_3.pkl"
output_path = "rf_compressed.pkl"

# Load original
model = joblib.load(input_path)

# Re-save with compression
# compress=3 → good balance between size and load speed
joblib.dump(model, output_path, compress=3)

print("Compressed model saved to:", output_path)