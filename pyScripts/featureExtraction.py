import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from tldextract import extract
import math

# Load raw URLs
data = pd.read_csv('/Users/rudrarajpurohit/Desktop/Active Ps/webshield-extension/pyScripts/datasets/urls_raw_650k.csv')

# Helper functions
def shannon_entropy(s):
    if len(s) == 0: return 0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob])

def longest_repeated_char(s):
    max_count = count = 1
    for i in range(1,len(s)):
        if s[i] == s[i-1]:
            count += 1
            max_count = max(max_count, count)
        else:
            count = 1
    return max_count

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    ext = extract(url)
    
    domain = ext.domain
    subdomain = ext.subdomain
    path = parsed.path
    query = parsed.query
    
    # 1. Basic structural
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_letters'] = sum(c.isalpha() for c in url)
    features['num_special_chars'] = sum(url.count(c) for c in ['@','?','=','%','&','!','+','$'])
    features['has_ip'] = int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc)))
    
    # 2. Domain / Host
    features['num_subdomains'] = len(subdomain.split('.')) if subdomain else 0
    features['domain_length'] = len(domain)
    features['host_entropy'] = shannon_entropy(domain)
    
    # 3. Path / Query
    features['path_length'] = len(path)
    features['num_path_segments'] = len([p for p in path.split('/') if p])
    features['num_query_params'] = len(query.split('&')) if query else 0
    features['query_length'] = len(query)
    features['num_encoded_chars'] = url.count('%')
    features['num_fragments'] = url.count('#')
    
    # 4. Keyword / Lexical
    suspicious_words = ['login','secure','update','account','verify','confirm','click','bank','paypal']
    features['suspicious_word'] = int(any(word in url.lower() for word in suspicious_words))
    features['sensitive_word'] = int(any(word in url.lower() for word in ['bank','paypal','account']))
    features['action_word'] = int(any(word in url.lower() for word in ['click','verify','confirm']))
    features['is_shortening_service'] = int(any(s in url for s in ['bit.ly','tinyurl','goo.gl']))
    features['is_mixed_case'] = int(any(c.isupper() for c in url) and any(c.islower() for c in url))
    
    # 5. Entropy / randomness
    features['url_entropy'] = shannon_entropy(url)
    features['path_entropy'] = shannon_entropy(path)
    features['domain_entropy'] = shannon_entropy(domain)
    features['num_repeated_chars'] = longest_repeated_char(url)
    features['longest_token_length'] = max([len(t) for t in re.split(r'[./?=&_-]', url)])
    
    # 6. Advanced / security
    features['suspicious_prefix_suffix'] = int('-' in domain)
    features['num_suspicious_symbols'] = sum(domain.count(c) for c in ['@','!','*'])
    
    return features

# Apply to all URLs
features_list = [extract_features(u) for u in data['url']]
features_df = pd.DataFrame(features_list)

# Add 29 feature columns to original CSV
result_df = pd.concat([data, features_df], axis=1)

# Save combined dataset
result_df.to_csv('urls_features_combined.csv', index=False)
print("✓ Feature extraction complete. Saved as 'urls_features_combined.csv'")
print(f"Total columns: {len(result_df.columns)}")
print(f"Original URL column + 29 features = {len(result_df.columns)} columns total")