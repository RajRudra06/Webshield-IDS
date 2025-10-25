# import pandas as pd

# def compare_six_csv_columns(*files):
#     """
#     Compare column names of six CSV files.
#     Prints whether all have the same columns in the same order.
#     """
#     if len(files) != 6:
#         print("❌ Please provide exactly six CSV file paths.")
#         return

#     try:
#         dfs = [pd.read_csv(f, nrows=0) for f in files]
#     except FileNotFoundError as e:
#         print(f"❌ File not found: {e.filename}")
#         return

#     cols = [list(df.columns) for df in dfs]

#     # Display file info
#     for i, (file, col_list) in enumerate(zip(files, cols), start=1):
#         print(f"📁 File {i}: {file} → {len(col_list)} columns")

#     print("\n" + "=" * 60)

#     # Check if all have identical columns in the same order
#     if all(col_list == cols[0] for col_list in cols[1:]):
#         print("✅ All six files have the same column names in the same order.")
#         return

#     print("❌ Column mismatch detected.\n")

#     # Gather all unique column names across all files
#     all_columns = set().union(*[set(c) for c in cols])

#     # Print per-file missing or extra columns
#     for i, col_list in enumerate(cols, start=1):
#         missing = all_columns - set(col_list)
#         extra = set(col_list) - all_columns
#         if missing or extra:
#             print(f"🔹 Differences in File {i}: {files[i-1]}")
#             if missing:
#                 print(f"   ❌ Missing columns: {sorted(missing)}")
#             if extra:
#                 print(f"   ⚠️ Extra columns: {sorted(extra)}")
#             print()
#         else:
#             print(f"✅ File {i} columns align with others.\n")

#     # Check if all have same columns but different order
#     if all(set(col_list) == set(cols[0]) for col_list in cols[1:]):
#         print("⚠️ All files have the same columns but not in the same order.")

# # --- Example usage ---
# if __name__ == "__main__":
#     compare_six_csv_columns(
#         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/phishing_8k.csv',
#         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/malware_8k.csv',
# #         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/defacement_8k.csv',
# #         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/benign_8k.csv',
# #         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/tranco_9k.csv',
# #         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/phishing_urls_4000.csv'
# #     )


# import pandas as pd

# def merge_six_csv(input_files, output_file='merged_6files.csv'):
#     """
#     Merge six CSV files that share identical columns (e.g., 'url', 'type').
#     Concatenates them vertically into a single CSV.
#     """
#     if len(input_files) != 6:
#         print("❌ Please provide exactly six CSV file paths.")
#         return

#     try:
#         dfs = [pd.read_csv(f) for f in input_files]
#     except FileNotFoundError as e:
#         print(f"❌ File not found: {e.filename}")
#         return

#     # Validate that all have the same columns
#     base_cols = list(dfs[0].columns)
#     if not all(list(df.columns) == base_cols for df in dfs):
#         print("⚠️ Warning: Not all files have identical column names or order.")
#         print(f"Expected columns: {base_cols}")
    
#     # Concatenate all files
#     merged_df = pd.concat(dfs, ignore_index=True)

#     # Save combined CSV
#     merged_df.to_csv(output_file, index=False)
#     print(f"✅ Merged {len(input_files)} files → {output_file}")
#     print(f"Total rows: {len(merged_df)}")

# # --- Example usage ---
# if __name__ == "__main__":
#     merge_six_csv([
#        '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/phishing_8k.csv',
#         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/malware_8k.csv',
#         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/defacement_8k.csv',
#         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/benign_8k.csv',
#         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/tranco_9k.csv',
#         '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/phishing_urls_4000.csv'
#                 ], output_file='merged_6files.csv')

import pandas as pd

def count_types(input_file):
    """
    Count rows by 'type' column: benign, malware, phishing, defacement.
    """
    df = pd.read_csv(input_file)

    # Normalize text to lowercase and strip spaces
    df['type'] = df['type'].astype(str).str.lower().str.strip()

    # Count occurrences
    counts = df['type'].value_counts()

    # Ensure all four categories are shown
    categories = ['benign', 'malware', 'phishing', 'defacement']
    print(f"📊 Counts in {input_file}:\n")
    for c in categories:
        print(f"{c.capitalize():<12}: {counts.get(c, 0)}")

    print(f"\nTotal rows: {len(df)}")

# Example usage:
count_types('/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/meta_learning.csv')

