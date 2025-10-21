import pandas as pd
import requests
from io import StringIO

def download_tranco_list(output_file='tranco_top10k.csv', top_n=10000):
    """
    Download Tranco top domains list
    """
    print(f"📥 Downloading Tranco top {top_n} domains...")
    
    # Tranco provides daily updated lists
    url = 'https://tranco-list.eu/top-1m.csv.zip'
    
    try:
        # Download and extract
        import zipfile
        from io import BytesIO
        
        response = requests.get(url)
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            with z.open('top-1m.csv') as f:
                df = pd.read_csv(f, names=['rank', 'domain'], nrows=top_n)
        
        df.to_csv(output_file, index=False)
        print(f"✅ Saved {len(df)} domains to {output_file}")
        return df
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Manual download: https://tranco-list.eu/")
        return None

def create_trusted_domains_dataset(tranco_file='tranco_top10k.csv', output_file='trusted_domains_with_features.csv'):
    """
    Create benign dataset from trusted domains with features
    """
    print("\n🔧 Creating trusted domains dataset...")
    
    # Load Tranco list
    tranco = pd.read_csv(tranco_file)
    
    # Create full URLs (add www prefix and https)
    tranco['url'] = 'https://www.' + tranco['domain']
    tranco['type'] = 'benign'
    
    # Extract features for each URL
    print(f"⚙️  Extracting features for {len(tranco)} trusted domains...")
    features_list = []
    for idx, url in enumerate(tranco['url']):
        if idx % 1000 == 0:
            print(f"  Processed {idx}/{len(tranco)} ({idx/len(tranco)*100:.1f}%)")
        features_list.append(extract_features_enhanced(url))
    
    features_df = pd.DataFrame(features_list)
    
    # Combine
    result = pd.concat([tranco[['url', 'type']], features_df], axis=1)
    result.to_csv(output_file, index=False)
    
    print(f"✅ Created trusted domains dataset: {output_file}")
    print(f"📊 Shape: {result.shape}")
    
    return result

def merge_datasets(original_file, trusted_file, output_file='merged_dataset_final.csv'):
    """
    Merge original dataset with trusted domains
    """
    print("\n🔗 Merging datasets...")
    
    # Load both
    original = pd.read_csv(original_file)
    trusted = pd.read_csv(trusted_file)
    
    print(f"📊 Original dataset: {original.shape}")
    print(f"📊 Trusted dataset: {trusted.shape}")
    
    # Ensure same columns
    common_cols = list(set(original.columns) & set(trusted.columns))
    
    original = original[common_cols]
    trusted = trusted[common_cols]
    
    # Merge
    merged = pd.concat([original, trusted], ignore_index=True)
    
    print(f"\n📊 Merged dataset shape: {merged.shape}")
    print(f"📊 Class distribution:")
    print(merged['type'].value_counts())
    
    # Save
    merged.to_csv(output_file, index=False)
    print(f"\n✅ Saved merged dataset to: {output_file}")
    
    return merged

# ============================================================
# COMPLETE PIPELINE
# ============================================================

def complete_data_preparation_pipeline():
    """
    Run complete pipeline to fix your dataset
    """
    print("="*70)
    print("🚀 STARTING COMPLETE DATA PREPARATION PIPELINE")
    print("="*70)
    
    # Step 1: Download Tranco
    print("\n" + "="*70)
    print("STEP 1: Download Trusted Domains (Tranco)")
    print("="*70)
    tranco_df = download_tranco_list('tranco_top10k.csv', top_n=10000)
    
    if tranco_df is None:
        print("❌ Failed to download Tranco. Please download manually.")
        return
    
    # Step 2: Extract features from original dataset
    print("\n" + "="*70)
    print("STEP 2: Extract Enhanced Features from Original Dataset")
    print("="*70)
    original_with_features = process_dataset(
        'urls_raw_650k.csv',
        'original_with_enhanced_features.csv'
    )
    
    # Step 3: Create trusted domains dataset with features
    print("\n" + "="*70)
    print("STEP 3: Create Trusted Domains Dataset with Features")
    print("="*70)
    trusted_with_features = create_trusted_domains_dataset(
        'tranco_top10k.csv',
        'trusted_domains_with_features.csv'
    )
    
    # Step 4: Merge everything
    print("\n" + "="*70)
    print("STEP 4: Merge All Datasets")
    print("="*70)
    final_dataset = merge_datasets(
        'original_with_enhanced_features.csv',
        'trusted_domains_with_features.csv',
        'final_training_dataset.csv'
    )
    
    print("\n" + "="*70)
    print("✅ PIPELINE COMPLETE!")
    print("="*70)
    print(f"\n📊 Final Dataset Statistics:")
    print(f"   Total samples: {len(final_dataset)}")
    print(f"   Total features: {len(final_dataset.columns) - 2}")  # Exclude url and type
    print(f"\n   Class Distribution:")
    for class_name, count in final_dataset['type'].value_counts().items():
        percentage = count / len(final_dataset) * 100
        print(f"   - {class_name:15s}: {count:6d} ({percentage:5.2f}%)")
    
    print(f"\n🎯 Next step: Train your model on 'final_training_dataset.csv'")
    
    return final_dataset

# Run the pipeline
if __name__ == "__main__":
    final_df = complete_data_preparation_pipeline()