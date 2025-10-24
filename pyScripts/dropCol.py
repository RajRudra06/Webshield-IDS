import pandas as pd

def drop_column(input_file, column_name, output_file=None):
    # Read CSV
    df = pd.read_csv(input_file)

    # Drop the specified column if it exists
    if column_name in df.columns:
        df = df.drop(columns=[column_name])
        print(f"✅ Dropped column: {column_name}")
    else:
        print(f"⚠️ Column '{column_name}' not found in {input_file}")
        return

    # Save back to same or new file
    output_file = output_file or input_file
    df.to_csv(output_file, index=False)
    print(f"💾 Saved updated CSV to: {output_file}")

# Example usage:
drop_column('/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/phishing_urls_4000.csv', 'seed')
