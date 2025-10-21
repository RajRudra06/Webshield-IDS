import pandas as pd

# --- Load CSV ---
file_path = '/Users/rudrarajpurohit/Desktop/datasets/latest /original_650k_with_features.csv'  # replace with your actual CSV file path
df = pd.read_csv(file_path)

# --- List columns ---
print("Number of columns:", len(df.columns))
print("Column names:")
for col in df.columns:
    print(col)

