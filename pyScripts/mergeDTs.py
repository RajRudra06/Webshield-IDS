"""
Script 5: Merge Original 650k + Tranco 50k + Synthetic datasets
Creates final ~751k dataset ready for training
"""

import pandas as pd

def merge_datasets(
    original_file='/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/original_650k_with_features_2.csv', 
    tranco_file='/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/tranco_top50k_with_features.csv',
    synthetic_file='/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/synthetic_phishing_with_features.csv',
    output_file='final_dataset_751k.csv'
):
    """
    Merge three datasets:
    1. Original 650k dataset
    2. Tranco 50k dataset
    3. Synthetic phishing examples (~1k)
    
    Ensures consistent columns and removes duplicates.
    """
    print("="*70)
    print("🔗 MERGING THREE DATASETS")
    print("="*70)
    
    # --- Load datasets ---
    print("\n📂 Loading datasets...")
    
    # Load Original
    try:
        original = pd.read_csv(original_file)
        print(f"  ✅ Original dataset:  {original.shape}")
    except FileNotFoundError:
        print(f"  ❌ Error: {original_file} not found!")
        print(f"  💡 Run 'extract_features_original.py' first")
        return None

    # Load Tranco
    try:
        tranco = pd.read_csv(tranco_file)
        print(f"  ✅ Tranco dataset:    {tranco.shape}")
    except FileNotFoundError:
        print(f"  ❌ Error: {tranco_file} not found!")
        print(f"  💡 Run 'extract_features_tranco.py' first")
        return None

    # Load Synthetic (optional - may not exist yet)
    try:
        synthetic = pd.read_csv(synthetic_file)
        print(f"  ✅ Synthetic dataset: {synthetic.shape}")
        has_synthetic = True
    except FileNotFoundError:
        print(f"  ⚠️  Synthetic file not found (skipping)")
        print(f"  💡 Generate it with 'generate_synthetic_phishing.py' if needed")
        synthetic = pd.DataFrame()  # Empty dataframe
        has_synthetic = False

    # --- Align columns ---
    print("\n📊 Column alignment...")
    
    # Get common columns across all datasets
    original_cols = set(original.columns)
    tranco_cols = set(tranco.columns)
    
    if has_synthetic:
        synthetic_cols = set(synthetic.columns)
        common_cols = sorted(list(original_cols & tranco_cols & synthetic_cols))
    else:
        common_cols = sorted(list(original_cols & tranco_cols))

    print(f"   Original columns:  {len(original_cols)}")
    print(f"   Tranco columns:    {len(tranco_cols)}")
    if has_synthetic:
        print(f"   Synthetic columns: {len(synthetic_cols)}")
    print(f"   Common columns:    {len(common_cols)}")

    # Validate essential columns exist
    if 'url' not in common_cols or 'type' not in common_cols:
        print("\n❌ Error: 'url' or 'type' column missing in one or more datasets.")
        return None

    # Keep only common columns
    original = original[common_cols]
    tranco = tranco[common_cols]
    if has_synthetic:
        synthetic = synthetic[common_cols]

    # --- Show class distributions before merge ---
    print("\n📊 Class distribution before merge:")
    print("\n  Original dataset:")
    for cls, count in original['type'].value_counts().items():
        print(f"    {cls:15s}: {count:7,}")
    
    print("\n  Tranco dataset:")
    for cls, count in tranco['type'].value_counts().items():
        print(f"    {cls:15s}: {count:7,}")
    
    if has_synthetic:
        print("\n  Synthetic dataset:")
        for cls, count in synthetic['type'].value_counts().items():
            print(f"    {cls:15s}: {count:7,}")

    # --- Merge datasets ---
    print("\n🔧 Merging datasets...")
    
    if has_synthetic:
        combined = pd.concat([original, tranco, synthetic], ignore_index=True)
        print(f"   Combined (original + tranco + synthetic): {combined.shape}")
    else:
        combined = pd.concat([original, tranco], ignore_index=True)
        print(f"   Combined (original + tranco): {combined.shape}")

    # --- Drop duplicates ---
    print("\n🧹 Removing duplicate URLs...")
    before_dedup = len(combined)
    combined.drop_duplicates(subset=['url'], inplace=True)
    after_dedup = len(combined)
    duplicates_removed = before_dedup - after_dedup
    
    print(f"   Before deduplication: {before_dedup:,}")
    print(f"   After deduplication:  {after_dedup:,}")
    print(f"   Duplicates removed:   {duplicates_removed:,}")

    # --- Shuffle dataset ---
    print("\n🔀 Shuffling dataset...")
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"   Dataset shuffled (random_state=42)")

    # --- Final class distribution ---
    print("\n📊 Final class distribution:")
    for cls, count in combined['type'].value_counts().items():
        percentage = (count / len(combined)) * 100
        print(f"   {cls:15s}: {count:7,} ({percentage:5.2f}%)")

    # --- Save final dataset ---
    combined.to_csv(output_file, index=False)
    print(f"\n💾 Saved merged dataset to: '{output_file}'")
    print(f"📊 Final dataset shape: {combined.shape}")
    
    # --- Summary ---
    print("\n" + "="*70)
    print("✅ MERGE COMPLETE!")
    print("="*70)
    print(f"\n📋 Summary:")
    print(f"   Total URLs:     {len(combined):,}")
    print(f"   Total Features: {len(combined.columns) - 2}")  # Excluding 'url' and 'type'
    print(f"   Output file:    {output_file}")
    print(f"\n🎯 Next step: Train your model on '{output_file}'")
    print("="*70)

    return combined


# --- Run script directly ---
if __name__ == "__main__":
    print("🚀 Starting dataset merge process...\n")
    
    # You can customize paths here
    result = merge_datasets(
        original_file='/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/original_650k_with_features.csv',
        tranco_file='/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/tranco_top40k_with_features.csv',
        synthetic_file='/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/synthetic_with_features.csv',
        output_file='final_dataset_751k.csv'
    )
    
    if result is not None:
        print("\n✅ Script completed successfully!")
    else:
        print("\n❌ Script failed. Check errors above.")

