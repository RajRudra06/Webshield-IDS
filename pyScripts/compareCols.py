import pandas as pd

def compare_three_csv_columns(file1, file2, file3):
    """
    Compare column names of three CSV files.
    Prints whether all have the same columns in the same order.
    """
    try:
        df1 = pd.read_csv(file1, nrows=0)
        df2 = pd.read_csv(file2, nrows=0)
        df3 = pd.read_csv(file3, nrows=0)
    except FileNotFoundError as e:
        print(f"❌ File not found: {e.filename}")
        return

    cols1, cols2, cols3 = list(df1.columns), list(df2.columns), list(df3.columns)

    print(f"📁 File 1: {file1} → {len(cols1)} columns")
    print(f"📁 File 2: {file2} → {len(cols2)} columns")
    print(f"📁 File 3: {file3} → {len(cols3)} columns\n")

    # Check if all three are identical
    if cols1 == cols2 == cols3:
        print("✅ All three files have the same column names in the same order.")
        return

    # Otherwise, find mismatches
    print("❌ Column mismatch detected.\n")

    # Unique columns per file
    print("🔹 Columns only in File 1:")
    print(set(cols1) - set(cols2) - set(cols3) or "None")

    print("\n🔹 Columns only in File 2:")
    print(set(cols2) - set(cols1) - set(cols3) or "None")

    print("\n🔹 Columns only in File 3:")
    print(set(cols3) - set(cols1) - set(cols2) or "None")

    # Check order mismatch
    if set(cols1) == set(cols2) == set(cols3):
        print("\n⚠️ All columns exist in all files but not in the same order.")

# --- Example usage ---
if __name__ == "__main__":
    compare_three_csv_columns(
        '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/original_650k_with_features.csv',
        '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/tranco_top40k_with_features.csv',
        '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/synthetic_with_features.csv'
    )
