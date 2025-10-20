import pandas as pd

# Load just 10 rows to see what's in there
df = pd.read_csv('/Users/rudrarajpurohit/Downloads/archive (1)/train_dataset.csv', nrows=10)

print("First 10 URLs:")
print(df['url'].head(10))

print("\nFirst 10 labels:")
print(df['label'].head(10))

print("\nColumn data types:")
print(df.dtypes)

print("\nSample row:")
print(df.iloc[0])