import pandas as pd

data = pd.read_csv('/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/urls_features_30.csv')
sampled_data = data.head(50000)  # or use data.sample(n=50000, random_state=42)
sampled_data.to_csv('urls_raw_50k.csv', index=False)
