"""
Script 4: Extract features for your original 650k dataset
Takes urls_raw_650k.csv and adds 45 features
"""

import pandas as pd
from feature_utils import batch_extract_features

def add_features_to_original(input_file, output_file='original_650k_with_features.csv'):
    """
    Extract 45 features for your original dataset
    """
    print("="*70)
    print("⚙️  EXTRACTING FEATURES FOR ORIGINAL DATASET")
    print("="*70)
    
    # Load original dataset
    print(f"\n📂 Loading {input_file}...")
    df = pd.read_csv(input_file)
    
    print(f"✅ Loaded {len(df):,} URLs")
    
    # Check if features already exist
    if 'url_length' in df.columns:
        print("\n⚠️  Features already exist in this dataset!")
        print("💡 Skipping feature extraction...")
        return df
    
    print(f"\n⚙️  Extracting 45 features per URL...")
    print(f"⏱️  Estimated time: ~15-25 minutes for 650k URLs")
    print(f"☕ This is a good time for a coffee break!\n")
    
    # Extract features with progress tracking
    features_df = batch_extract_features(df['url'], progress_interval=10000)
    
    print(f"\n✅ Feature extraction complete!")
    print(f"📊 Features extracted: {len(features_df.columns)}")
    
    # Combine with original data (keep url and type columns)
    result = pd.concat([df[['url', 'type']], features_df], axis=1)
    
    # Save
    result.to_csv(output_file, index=False)
    print(f"\n💾 Saved to: {output_file}")
    print(f"📊 Final shape: {result.shape}")
    
    # Show class distribution
    print(f"\n📊 Class Distribution:")
    for class_name, count in result['type'].value_counts().items():
        percentage = (count / len(result)) * 100
        print(f"   {class_name:15s}: {count:7,} ({percentage:5.2f}%)")
    
    return result

if __name__ == "__main__":
    print("🚀 Starting Feature Extraction for Original Dataset\n")
    
    # Update this path to your actual dataset location
    INPUT_FILE = '/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/phishing_urls_35000.csv'
    # Check if file exists
    import os
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: {INPUT_FILE} not found!")
        print("💡 Please update INPUT_FILE path in script")
        exit(1)
    
    # Extract features
    df = add_features_to_original(INPUT_FILE, 'synthetic_with_features.csv')
    
    if df is not None:
        print("\n✅ Script completed successfully!")
        print(f"📊 Next step: Run 'merge_datasets.py' to combine both datasets")
    else:
        print("\n❌ Script failed. Please check errors above.")


