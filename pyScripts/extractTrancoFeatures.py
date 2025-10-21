"""
Script 3: Extract features for Tranco domains
Takes tranco_top50k.csv and adds 45 features
"""

import pandas as pd
from feature_utils import batch_extract_features

def add_features_to_tranco(input_file='tranco_top50k.csv', output_file='tranco_top50k_with_features.csv'):
    """
    Extract 60 features for all Tranco domains
    """
    print("="*70)
    print("⚙️  EXTRACTING FEATURES FOR TRANCO DOMAINS")
    print("="*70)
    
    # Load Tranco
    print(f"\n📂 Loading {input_file}...")
    df = pd.read_csv(input_file)
    
    print(f"✅ Loaded {len(df):,} URLs")
    print(f"\n⚙️  Extracting 45 features per URL...")
    print(f"⏱️  Estimated time: ~10-15 minutes for 50k URLs\n")
    
    # Extract features with progress tracking
    features_df = batch_extract_features(df['url'], progress_interval=5000)
    
    print(f"\n✅ Feature extraction complete!")
    print(f"📊 Features extracted: {len(features_df.columns)}")
    
    # Combine with original data (keep url and type columns)
    result = pd.concat([df[['url', 'type']], features_df], axis=1)
    
    # Save
    result.to_csv(output_file, index=False)
    print(f"\n💾 Saved to: {output_file}")
    print(f"📊 Final shape: {result.shape}")
    print(f"📊 Columns: {list(result.columns[:10])}... (showing first 10)")
    
    return result

if __name__ == "__main__":
    print("🚀 Starting Feature Extraction for Tranco\n")
    
    # Check if Tranco file exists
    import os
    if not os.path.exists('./tranco_top40k.csv'):
        print("❌ Error: tranco_top50k.csv not found!")
        print("💡 Please run 'download_tranco.py' first")
        exit(1)
    
    # Extract features
    df = add_features_to_tranco('tranco_top40k.csv', 'tranco_top40k_with_features.csv')
    
    if df is not None:
        print("\n✅ Script completed successfully!")
        print(f"📊 Next step: Run 'extract_features_original.py' for your 650k dataset")
    else:
        print("\n❌ Script failed. Please check errors above.")

