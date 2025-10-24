import pandas as pd

def make_benign_subset(input_file, output_file='phishing_8k.csv', sample_size=1000):
    # Read the source CSV
    df = pd.read_csv(input_file)

    # Filter only rows where type == benign (case-insensitive)
    benign_df = df[df['type'].str.lower() == 'phishing']

    # Choose up to 8,000 rows
    if len(benign_df) > sample_size:
        benign_subset = benign_df.sample(n=sample_size, random_state=42)
    else:
        benign_subset = benign_df

    # Save the filtered data with all columns preserved
    benign_subset.to_csv(output_file, index=False)

    print(f"✅ Extracted {len(benign_subset)} phishing rows")
    print(f"💾 Saved to {output_file}")

# Example:
make_benign_subset('/Users/rudrarajpurohit/Downloads/Malicious URL v3.csv', 'phishing_8k.csv')
