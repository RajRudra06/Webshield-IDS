"""
Script: Download Tranco Top 40k Domains
Downloads and saves top 40,000 domains from Tranco list
Balanced with synthetic phishing for 1:1 training ratio
"""

import pandas as pd
import requests
from io import BytesIO
import zipfile

def download_tranco_top40k(output_file='tranco_top40k.csv'):
    """
    Download Tranco top 40,000 domains
    Includes global + Indian major sites
    """
    print("=" * 70)
    print("📥 DOWNLOADING TRANCO TOP 40K DOMAINS")
    print("=" * 70)
    print("\nThis includes:")
    print("  ✅ All major global sites (Google, Facebook, Amazon, etc.)")
    print("  ✅ All Indian banks (ICICI, HDFC, SBI, Axis, Kotak, etc.)")
    print("  ✅ All Indian payment apps (Paytm, PhonePe, GooglePay, etc.)")
    print("  ✅ All Indian e-commerce (Flipkart, Myntra, Snapdeal, etc.)")
    print("  ✅ All Indian services (IRCTC, Swiggy, Zomato, Ola, etc.)")
    print("\n📡 Downloading from Tranco...\n")
    
    try:
        url = 'https://tranco-list.eu/top-1m.csv.zip'
        print("⏳ Downloading... (this may take 30–60 s)")
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        print("✅ Download complete! Extracting...")

        with zipfile.ZipFile(BytesIO(response.content)) as z:
            with z.open('top-1m.csv') as f:
                df = pd.read_csv(f, names=['rank', 'domain'], nrows=40000)  # 40K only

        print(f"✅ Extracted {len(df):,} domains")

        # Clean and build final dataset
        df['url'] = 'https://www.' + df['domain'].astype(str)
        df['type'] = 'benign'

        # Save
        df.to_csv(output_file, index=False)
        print(f"\n💾 Saved to: {output_file}")

        # Summary sample coverage
        print("\n" + "=" * 70)
        print("📊 COVERAGE CHECK – SAMPLE SITES")
        print("=" * 70)
        test_sites = {
            '🌐 Global': ['google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'microsoft.com'],
            '🏦 Indian Banks': ['icicibank.com', 'hdfcbank.com', 'sbi.co.in', 'axisbank.com', 'kotak.com'],
            '💳 Payment Apps': ['paytm.com', 'phonepe.com', 'mobikwik.com'],
            '🛒 E-commerce': ['flipkart.com', 'myntra.com', 'snapdeal.com', 'nykaa.com'],
            '🍔 Food/Services': ['swiggy.com', 'zomato.com', 'irctc.co.in', 'makemytrip.com'],
        }

        for category, sites in test_sites.items():
            print(f"\n{category}:")
            found = 0
            for site in sites:
                if site in df['domain'].values:
                    rank = df.loc[df['domain'] == site, 'rank'].values[0]
                    print(f"  ✅ {site:25s} (Rank: {rank:,})")
                    found += 1
                else:
                    print(f"  ⚠️  {site:25s} (Not in top 40k)")
            print(f"  Coverage: {found}/{len(sites)}")

        print("\n" + "=" * 70)
        print(f"✅ Successfully downloaded {len(df):,} benign domains")
        print(f"💾 File saved: {output_file}")
        print("=" * 70)

        return df

    except requests.exceptions.RequestException as e:
        print(f"\n❌ Error downloading Tranco: {e}")
        print("Manual download steps:")
        print("  1. Visit: https://tranco-list.eu/")
        print("  2. Download latest top-1m.zip")
        print("  3. Extract and take first 40 000 rows")
        print("  4. Save as tranco_top40k.csv with columns: rank, domain, url, type")
        return None
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return None


if __name__ == "__main__":
    print("🚀 Starting Tranco Download Script\n")
    df = download_tranco_top40k('tranco_top40k.csv')
    if df is not None:
        print("\n✅ Script completed successfully!")
        print("📊 Next step: run feature extraction for benign data")
    else:
        print("\n❌ Script failed. Please check errors above.")

