import pandas as pd

# Assuming your features CSV is loaded
features_df = pd.read_csv('/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/urls_features_combined.csv')

# Display first 10 rows
print(features_df.head(10))


import pandas as pd

df = pd.read_csv('urls_features_combined.csv')
print(f"Total columns: {len(df.columns)}\n")
print("All columns:")
for i, col in enumerate(df.columns, 1):
    print(f"{i}. {col}")