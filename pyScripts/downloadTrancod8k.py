"""
Download Tranco domains:
 - first 1,000 (ranks 1–1,000)
 - next 8,000 after top 40k (ranks 40,001–48,000)
Output: tranco_9k.csv (9,000 rows total)
"""

import pandas as pd
import requests
from io import BytesIO
import zipfile

def download_tranco_9k(output_file='tranco_9k.csv'):
    url = 'https://tranco-list.eu/top-1m.csv.zip'
    print("Downloading Tranco list...")
    response = requests.get(url, timeout=60)
    response.raise_for_status()

    with zipfile.ZipFile(BytesIO(response.content)) as z:
        with z.open('top-1m.csv') as f:
            df = pd.read_csv(f, names=['rank', 'domain'], nrows=48000)

    # Take top 1k + 8k after rank 40k
    df_1k = df.iloc[:1000]
    df_8k = df.iloc[40000:48000]
    df_final = pd.concat([df_1k, df_8k], ignore_index=True)

    # Add URL and label
    df_final['url'] = 'https://www.' + df_final['domain'].astype(str)
    df_final['type'] = 'benign'

    df_final.to_csv(output_file, index=False)
    print(f"✅ Saved combined 9,000 domains to {output_file}")

    return df_final

if __name__ == "__main__":
    download_tranco_9k()
